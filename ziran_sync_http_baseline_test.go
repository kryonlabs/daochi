package main

// Original sync HTTP orchestration at b9936b0.
import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func (s *Server) baselineSyncHTTPHandleSync(w http.ResponseWriter, r *http.Request) {
	s.Metrics.SyncRequests.Add(1)
	syncOK := false
	var signedTx *SignedTxEnvelope
	defer func() {
		if !syncOK {
			s.Metrics.SyncFailures.Add(1)
			if signedTx != nil {
				SignedTx_Forget(s.Store.Database, r.Context(), *signedTx)
			}
		}
	}()
	bodyResult := HttpBody_ReadJSON(w, r, s.Cfg.MaxBodyBytes)
	body, err := bodyResult.Value, bodyResult.Error
	if err != nil {
		Response_Error(w, http.StatusBadRequest, err.Error())
		return
	}
	if SyncRequest_IsEncryptedEnvelope(body) {
		if s.baselineSyncHTTPHandleEncryptedSyncEnvelope(w, r, body) {
			syncOK = true
		}
		return
	}
	parsed := SyncRequest_ParseSync(body)
	req, err := parsed.Value, parsed.Error
	if err != nil {
		Response_Error(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := SyncRequest_ApplyHeaderUser(r, &req.UserIDHash); err != nil {
		Response_Error(w, http.StatusBadRequest, err.Error())
		return
	}
	if !Identity_ValidClientID(req.ClientID) {
		Response_Error(w, http.StatusBadRequest, "invalid client_id")
		return
	}
	tokenUser, err := s.baselineAuthenticateToken(r)
	if err != nil {
		s.baselineWriteAuthError(w, err)
		return
	}
	if tokenUser != req.UserIDHash {
		Response_Error(w, http.StatusUnauthorized, "token user mismatch")
		return
	}
	decodedKey := SyncRequest_PublicKey(req)
	publicKey, err := decodedKey.Value, decodedKey.Error
	if err != nil {
		Response_Error(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.baselineSyncHTTPValidateSyncRequest(r.Context(), req); err != nil {
		Response_Error(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.ProtocolVersion >= 6 {
		header := SignedTx_ReadHeader(r)
		tx, err := header.Value, baselineAuthenticationError(header.Authentication)
		if err != nil {
			s.baselineWriteAuthError(w, err)
			return
		}
		if err := baselineAuthenticationError(SignedTx_Verify(s.Store.Database, r.Context(), r, body, tx, req.UserIDHash, req.AppID, s.Verifier.Verify, errSignedTxReplay)); err != nil {
			s.baselineWriteAuthError(w, err)
			return
		}
		signedTx = &tx
	}
	SyncRequest_NormalizeMeditationDurations(req.MeditationLogs)

	baseHash, err := s.Store.StateHash(r.Context(), req.UserIDHash)
	if err != nil {
		slog.Error("hash sync state", "user", LogSafety_LogText(req.UserIDHash), "error", err)
		Response_Error(w, http.StatusInternalServerError, "state hash failed")
		return
	}

	result := SyncResult{}
	acceptedOps := []string{}
	remoteOps := []SyncOp{}
	fullSnapshotRequired := false
	changesComplete := true
	sinceVersion := req.SinceServerVersion
	recordedClientClock := req.ClientClock
	snapshotReason := ""
	compactedThrough := int64(0)
	if req.LastServerStateHash != "" &&
		!strings.EqualFold(req.LastServerStateHash, baseHash) &&
		!req.FullSyncRequested {
		fullSnapshotRequired = true
		changesComplete = false
		sinceVersion = 0
		snapshotReason = "state_hash_mismatch"
	} else if req.ProtocolVersion >= 2 && !req.FullSyncRequested {
		compacted, through, err := s.Store.SyncOpsCompacted(r.Context(), req.UserIDHash, req.ClientClock)
		if err != nil {
			slog.Error("check sync op compaction", "user", LogSafety_LogText(req.UserIDHash), "error", err)
			Response_Error(w, http.StatusInternalServerError, "compaction check failed")
			return
		}
		compactedThrough = through
		if compacted {
			fullSnapshotRequired = true
			changesComplete = false
			sinceVersion = 0
			snapshotReason = "sync_ops_compacted"
		} else {
			result, acceptedOps, err = s.Store.ApplySyncDetailed(r.Context(), req, publicKey)
			if err != nil {
				slog.Error("apply sync", "user", LogSafety_LogText(req.UserIDHash), "error", err)
				Response_Error(w, http.StatusInternalServerError, "sync failed")
				return
			}
		}
	} else {
		result, acceptedOps, err = s.Store.ApplySyncDetailed(r.Context(), req, publicKey)
		if err != nil {
			slog.Error("apply sync", "user", LogSafety_LogText(req.UserIDHash), "error", err)
			Response_Error(w, http.StatusInternalServerError, "sync failed")
			return
		}
	}
	if fullSnapshotRequired && SyncRequest_HasLocalChanges(req) {
		result, acceptedOps, err = s.Store.ApplySyncDetailed(r.Context(), req, publicKey)
		if err != nil {
			slog.Error("apply stale sync uploads", "user", LogSafety_LogText(req.UserIDHash), "error", err)
			Response_Error(w, http.StatusInternalServerError, "sync failed")
			return
		}
	}
	if fullSnapshotRequired {
		Metrics_RecordFullSnapshot(s.Metrics, snapshotReason)
	}

	changes, serverVersion, err := s.Store.ChangesSince(r.Context(), req.UserIDHash, sinceVersion)
	if err != nil {
		slog.Error("load sync changes", "user", LogSafety_LogText(req.UserIDHash), "error", err)
		Response_Error(w, http.StatusInternalServerError, "changes failed")
		return
	}
	changes.SocialCache, err = s.Store.AuthoritativeSocial(r.Context(), req.UserIDHash)
	if err != nil {
		slog.Error("load authoritative social state", "user", LogSafety_LogText(req.UserIDHash), "error", err)
		Response_Error(w, http.StatusInternalServerError, "social state failed")
		return
	}
	if req.ProtocolVersion >= 2 {
		if fullSnapshotRequired {
			remoteOps = []SyncOp{}
			recordedClientClock = serverVersion
		} else {
			remoteOps, err = s.Store.OpsSince(r.Context(), req.UserIDHash, req.ClientClock)
			if err != nil {
				slog.Error("load sync ops", "user", LogSafety_LogText(req.UserIDHash), "error", err)
				Response_Error(w, http.StatusInternalServerError, "ops failed")
				return
			}
		}
	}
	serverHash, err := s.Store.StateHash(r.Context(), req.UserIDHash)
	if err != nil {
		slog.Error("hash sync response", "user", LogSafety_LogText(req.UserIDHash), "error", err)
		Response_Error(w, http.StatusInternalServerError, "state hash failed")
		return
	}
	if err := s.Store.RecordClientSync(r.Context(), req.UserIDHash, req.ClientID, req.SinceServerVersion, serverVersion, req.ProtocolVersion, recordedClientClock); err != nil {
		slog.Error("record sync client", "user", LogSafety_LogText(req.UserIDHash), "client", LogSafety_LogText(req.ClientID), "error", err)
		Response_Error(w, http.StatusInternalServerError, "client state failed")
		return
	}
	if req.ProtocolVersion >= 2 {
		if err := s.Store.CompactSyncOps(r.Context(), req.UserIDHash); err != nil {
			slog.Error("compact sync ops", "user", LogSafety_LogText(req.UserIDHash), "error", err)
			Response_Error(w, http.StatusInternalServerError, "compaction failed")
			return
		}
	}
	if baselineSyncHTTPSyncResultApplied(result) {
		SyncHub_Publish(s.SyncHub, req.UserIDHash, serverVersion)
	}
	accountAlias, err := s.Store.AccountAlias(r.Context(), req.UserIDHash)
	if err != nil {
		slog.Error("load account alias", "user", LogSafety_LogText(req.UserIDHash), "error", err)
		Response_Error(w, http.StatusInternalServerError, "alias failed")
		return
	}
	profileIcon, err := s.Store.AccountProfileIcon(r.Context(), req.UserIDHash)
	if err != nil {
		slog.Error("load profile icon", "user", LogSafety_LogText(req.UserIDHash), "error", err)
		Response_Error(w, http.StatusInternalServerError, "profile icon failed")
		return
	}
	response := SyncResponse{
		ProtocolVersion:      req.ProtocolVersion,
		Status:               "ok",
		ServerCapabilities:   NodeInfo_Capabilities(),
		TransitionMode:       SyncRequest_TransitionMode(req),
		Applied:              result,
		AccountAlias:         accountAlias,
		ProfileIcon:          profileIcon,
		ServerVersion:        serverVersion,
		ServerClock:          serverVersion,
		ServerStateHash:      serverHash,
		BaseStateHash:        baseHash,
		ChangesComplete:      changesComplete,
		FullSnapshotRequired: fullSnapshotRequired,
		AcceptedOps:          acceptedOps,
		Ops:                  remoteOps,
		Changes:              changes,
		MinSupportedProtocol: MinSupportedProtocol,
		LatestProtocol:       req.ProtocolVersion,
		ServerLatestProtocol: LatestProtocol,
		Diagnostics: &SyncDiagnostics{
			SnapshotReason:              snapshotReason,
			RequestedSinceServerVersion: req.SinceServerVersion,
			EffectiveSinceServerVersion: sinceVersion,
			ClientClock:                 req.ClientClock,
			CompactedThroughVersion:     compactedThrough,
			HasLocalChanges:             SyncRequest_HasLocalChanges(req),
			AcceptedOps:                 len(acceptedOps),
			RemoteOps:                   len(remoteOps),
			AppliedInput:                result,
			ReturnedChanges:             baselineSyncHTTPSyncChangesResult(changes),
		},
	}
	if req.ProtocolVersion >= 3 {
		if err := s.Store.AutoMigrateAccountForProtocol(r.Context(), req.UserIDHash, req.ProtocolVersion); err != nil {
			slog.Error("auto migrate account", "user", LogSafety_LogText(req.UserIDHash), "error", err)
			Response_Error(w, http.StatusInternalServerError, "migration failed")
			return
		}
		serverVersion, err = s.Store.currentUserVersion(r.Context(), req.UserIDHash)
		if err != nil {
			slog.Error("load migrated server version", "user", LogSafety_LogText(req.UserIDHash), "error", err)
			Response_Error(w, http.StatusInternalServerError, "version failed")
			return
		}
		serverHash, err = s.Store.StateHash(r.Context(), req.UserIDHash)
		if err != nil {
			slog.Error("hash migrated sync response", "user", LogSafety_LogText(req.UserIDHash), "error", err)
			Response_Error(w, http.StatusInternalServerError, "state hash failed")
			return
		}
		response.ServerVersion = serverVersion
		response.ServerClock = serverVersion
		response.ServerStateHash = serverHash
		response.Data, err = s.Store.CleanData(r.Context(), req.UserIDHash)
		if err != nil {
			slog.Error("load clean data", "user", LogSafety_LogText(req.UserIDHash), "error", err)
			Response_Error(w, http.StatusInternalServerError, "clean data failed")
			return
		}
		if !SyncRequest_IncludeLegacyPrivateData(req) {
			response.Data.Habits = []Habit{}
			response.Data.HabitDays = []CleanHabitDay{}
			response.Data.Sessions = []Session{}
			response.Data.MeditationLogs = []MeditationLog{}
		}
		response.Changes.Habits = response.Data.Habits
		response.Changes.HabitDays = make([]HabitDay, 0, len(response.Data.HabitDays))
		for _, day := range response.Data.HabitDays {
			response.Changes.HabitDays = append(response.Changes.HabitDays, HabitDay{
				HabitID:   day.HabitID,
				LocalDate: day.LocalDate,
				Completed: day.Completed,
				Count:     day.Count,
				UpdatedAt: day.UpdatedAt,
			})
		}
		response.Changes.Sessions = response.Data.Sessions
		response.Changes.MeditationLogs = response.Data.MeditationLogs
		response.Changes.SocialCache = response.Data.Social
		response.Changes.EncryptedRecords = response.Data.EncryptedRecords
		response.Logs, err = s.Store.SyncLogs(r.Context(), req.UserIDHash, req.ClientClock)
		if err != nil {
			slog.Error("load sync logs", "user", LogSafety_LogText(req.UserIDHash), "error", err)
			Response_Error(w, http.StatusInternalServerError, "logs failed")
			return
		}
		response.Deletes, err = s.Store.DeleteLogs(r.Context(), req.UserIDHash, req.ClientClock)
		if err != nil {
			slog.Error("load delete logs", "user", LogSafety_LogText(req.UserIDHash), "error", err)
			Response_Error(w, http.StatusInternalServerError, "delete logs failed")
			return
		}
		response.LegacyClients, err = s.Store.LegacyClients(
			r.Context(), req.UserIDHash, LatestProtocol)
		if err != nil {
			slog.Error("load legacy clients", "user", LogSafety_LogText(req.UserIDHash), "error", err)
			Response_Error(w, http.StatusInternalServerError, "legacy clients failed")
			return
		}
		if len(response.LegacyClients) > 0 {
			s.Metrics.LegacyClientHints.Add(uint64(len(response.LegacyClients)))
		}
	}
	response.LegacyWriteRequired, response.LegacyProjectionEpoch, err =
		s.Store.LegacyWritePolicy(r.Context(), req.UserIDHash)
	if err != nil {
		slog.Error("load legacy write policy", "user", LogSafety_LogText(req.UserIDHash), "error", err)
		Response_Error(w, http.StatusInternalServerError, "legacy write policy failed")
		return
	}
	if response.Diagnostics != nil {
		response.Diagnostics.ReturnedChanges = baselineSyncHTTPSyncChangesResult(response.Changes)
	}
	if result.EncryptedRecords > 0 {
		s.Metrics.SyncEncryptedRecords.Add(uint64(result.EncryptedRecords))
	}
	if err := s.Store.RecordSyncAudit(r.Context(), SyncAuditEntry{
		UserIDHash:           req.UserIDHash,
		ClientID:             req.ClientID,
		AppID:                req.AppID,
		ProtocolVersion:      req.ProtocolVersion,
		SinceServerVersion:   req.SinceServerVersion,
		ClientClock:          req.ClientClock,
		ServerVersion:        response.ServerVersion,
		Applied:              result,
		RemoteOps:            len(remoteOps),
		FullSnapshotRequired: fullSnapshotRequired,
		SnapshotReason:       snapshotReason,
	}); err != nil {
		slog.Error("record sync audit", "user", LogSafety_LogText(req.UserIDHash), "client", LogSafety_LogText(req.ClientID), "error", err)
	}
	syncOK = true
	Response_JSON(w, http.StatusOK, response)
}

func (s *Server) baselineSyncHTTPHandleEncryptedSyncEnvelope(w http.ResponseWriter, r *http.Request, body []byte) bool {
	userHeader := HttpAuth_UserHeader(r)
	userID, headerName := userHeader.Value, userHeader.Name
	if userID == "" {
		Response_Error(w, http.StatusBadRequest, "missing X-Daochi-User")
		return false
	}
	if !Identity_ValidUserID(userID) {
		Response_Error(w, http.StatusBadRequest, "invalid "+headerName)
		return false
	}
	tokenUser, err := s.baselineAuthenticateToken(r)
	if err != nil {
		s.baselineWriteAuthError(w, err)
		return false
	}
	if tokenUser != userID {
		s.baselineWriteAuthError(w, authError{status: http.StatusUnauthorized, message: "token user mismatch"})
		return false
	}
	clientID := HttpAuth_HeaderAlias(r, []string{"X-Daochi-Client", "X-Ksync-Client"})
	if clientID != "" && !Identity_ValidClientID(clientID) {
		Response_Error(w, http.StatusBadRequest, "invalid X-Daochi-Client")
		return false
	}
	sinceVersion := int64(0)
	if text := HttpAuth_HeaderAlias(r, []string{"X-Daochi-Since-Version", "X-Ksync-Since-Version"}); text != "" {
		parsed, err := strconv.ParseInt(text, 10, 64)
		if err != nil || parsed < 0 {
			Response_Error(w, http.StatusBadRequest, "invalid X-Daochi-Since-Version")
			return false
		}
		sinceVersion = parsed
	}
	payloadLimit := SyncRequest_EncryptedPayloadLimit(r, s.Cfg.EncryptedPayloadMaxReturn)
	limit, err := payloadLimit.Value, payloadLimit.Error
	if err != nil {
		Response_Error(w, http.StatusBadRequest, err.Error())
		return false
	}
	if s.Cfg.EncryptedPayloadMaxAccountBytes > 0 {
		currentBytes, err := s.Store.EncryptedPayloadBytes(r.Context(), userID)
		if err != nil {
			slog.Error("load encrypted payload usage", "user", LogSafety_LogText(userID), "error", err)
			Response_Error(w, http.StatusInternalServerError, "encrypted sync failed")
			return false
		}
		if int64(len(body)) > s.Cfg.EncryptedPayloadMaxAccountBytes ||
			currentBytes+int64(len(body)) > s.Cfg.EncryptedPayloadMaxAccountBytes {
			Response_Error(w, http.StatusRequestEntityTooLarge, "encrypted payload quota exceeded")
			return false
		}
	}
	accountAlias, err := s.Store.AccountAlias(r.Context(), userID)
	if err != nil {
		slog.Error("load encrypted sync account alias", "user", LogSafety_LogText(userID), "error", err)
		Response_Error(w, http.StatusInternalServerError, "alias failed")
		return false
	}
	profileIcon, err := s.Store.AccountProfileIcon(r.Context(), userID)
	if err != nil {
		slog.Error("load encrypted sync profile icon", "user", LogSafety_LogText(userID), "error", err)
		Response_Error(w, http.StatusInternalServerError, "profile icon failed")
		return false
	}
	social, err := s.Store.AuthoritativeSocial(r.Context(), userID)
	if err != nil {
		slog.Error("load encrypted sync social state", "user", LogSafety_LogText(userID), "error", err)
		Response_Error(w, http.StatusInternalServerError, "social state failed")
		return false
	}
	serverVersion, err := s.Store.StoreEncryptedPayload(r.Context(), userID, clientID, body)
	if err != nil {
		if errors.Is(err, ErrSyncUserNotFound) {
			Response_Error(w, http.StatusNotFound, "sync account not found")
			return false
		}
		slog.Error("store encrypted payload", "user", LogSafety_LogText(userID), "error", err)
		Response_Error(w, http.StatusInternalServerError, "encrypted sync failed")
		return false
	}
	if result, err := s.Store.PruneEncryptedPayloads(r.Context(), userID, s.Cfg.EncryptedPayloadRetention, 0); err != nil {
		slog.Error("prune encrypted payloads", "user", LogSafety_LogText(userID), "error", err)
	} else if result.Deleted > 0 {
		slog.Info("pruned encrypted payloads", "user", LogSafety_LogText(userID), "deleted", result.Deleted)
	}
	payloads, truncated, err := s.Store.EncryptedPayloadsSince(r.Context(), userID, sinceVersion, limit)
	if err != nil {
		slog.Error("load encrypted payloads", "user", LogSafety_LogText(userID), "error", err)
		Response_Error(w, http.StatusInternalServerError, "encrypted sync failed")
		return false
	}
	if err := s.Store.RecordClientSync(r.Context(), userID, clientID, sinceVersion, serverVersion, LatestProtocol, serverVersion); err != nil {
		slog.Error("record encrypted sync client", "user", LogSafety_LogText(userID), "client", LogSafety_LogText(clientID), "error", err)
	}
	if err := s.Store.RecordSyncAudit(r.Context(), SyncAuditEntry{
		UserIDHash:            userID,
		ClientID:              clientID,
		ProtocolVersion:       LatestProtocol,
		SinceServerVersion:    sinceVersion,
		ClientClock:           sinceVersion,
		ServerVersion:         serverVersion,
		EncryptedPayload:      true,
		EncryptedPayloadBytes: int64(len(body)),
	}); err != nil {
		slog.Error("record encrypted sync audit", "user", LogSafety_LogText(userID), "client", LogSafety_LogText(clientID), "error", err)
	}
	s.Metrics.SyncEncryptedPayloads.Add(1)
	SyncHub_Publish(s.SyncHub, userID, serverVersion)
	response := SyncResponse{
		ProtocolVersion:      LatestProtocol,
		Status:               "ok",
		ServerCapabilities:   NodeInfo_Capabilities(),
		TransitionMode:       "encrypted_payload",
		AccountAlias:         accountAlias,
		ProfileIcon:          profileIcon,
		ServerVersion:        serverVersion,
		ServerClock:          serverVersion,
		ChangesComplete:      true,
		Changes:              SyncRequest_EmptyChanges(),
		EncryptedPayloads:    payloads,
		MinSupportedProtocol: MinSupportedProtocol,
		ServerLatestProtocol: LatestProtocol,
	}
	response.Changes.SocialCache = social
	if truncated {
		response.EncryptedPayloadsTruncated = true
		response.EncryptedPayloadsNextSinceVersion = payloads[len(payloads)-1].ServerVersion
	}
	Response_JSON(w, http.StatusOK, response)
	return true
}

func (s *Server) baselineSyncHTTPValidateSyncRequest(ctx context.Context, req SyncRequest) error {
	if req.AppID != "" {
		if !Identity_ValidNamespace(req.AppID) {
			return errors.New("invalid app_id")
		}
		appResult := AppStore_ByID(s.Store.Database, ctx, req.AppID)
		app, exists, err := appResult.Value, appResult.Found, appResult.Error
		if err != nil {
			return err
		}
		if !exists {
			return errors.New("unknown app_id")
		}
		if app.Status != "active" {
			return errors.New("app_id inactive")
		}
		if req.ProtocolVersion >= 6 && app.ManifestExpiresAt > 0 &&
			time.Now().Unix() > app.ManifestExpiresAt {
			return errors.New("app manifest expired")
		}
		if req.ProtocolVersion < 6 {
			legacyResult := AppStore_AllowsLegacyProtocol(s.Store.Database, ctx, req.AppID, req.ProtocolVersion)
			allowed, err := legacyResult.Value, legacyResult.Error
			if err != nil {
				return err
			}
			if !allowed {
				return errors.New("legacy protocol not allowed for app_id")
			}
		}
	}
	if req.ProtocolVersion >= 6 && req.AppID == "" {
		return errors.New("app_id required")
	}
	for _, item := range req.EncryptedRecords {
		if !EncryptedRecord_ValidForProtocol(item, req.ProtocolVersion) {
			return errors.New("invalid encrypted record")
		}
		if req.AppID != "" {
			ownership := AppStore_OwnsCollection(s.Store.Database, ctx, req.AppID, item.Collection)
			owns, err := ownership.Value, ownership.Error
			if err != nil {
				return err
			}
			if !owns {
				if req.ProtocolVersion >= 6 {
					return errors.New("encrypted record collection is not registered for app_id")
				}
				slog.Warn("sync request used unregistered app collection", "app_id", LogSafety_LogText(req.AppID), "collection", LogSafety_LogText(item.Collection), "mode", "compat")
			}
		}
	}
	return nil
}

func baselineSyncHTTPSyncResultApplied(result SyncResult) bool {
	return result.MeditationLogs > 0 ||
		result.Habits > 0 ||
		result.HabitDays > 0 ||
		result.Sessions > 0 ||
		result.SocialCache > 0 ||
		result.EncryptedRecords > 0
}

func baselineSyncHTTPSyncChangesResult(changes SyncChanges) SyncResult {
	return SyncResult{
		MeditationLogs:   len(changes.MeditationLogs),
		Habits:           len(changes.Habits),
		HabitDays:        len(changes.HabitDays),
		Sessions:         len(changes.Sessions),
		SocialCache:      len(changes.SocialCache),
		EncryptedRecords: len(changes.EncryptedRecords),
	}
}
