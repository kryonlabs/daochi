// Original profile and friend HTTP handlers retained as a regression oracle.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
)

func (s *Server) baselineSocialHttpHandleAlias(w http.ResponseWriter, r *http.Request) {
	_, req, err := baselineSocialHttpReadAliasRequest(w, r, s.Cfg.MaxBodyBytes)
	if err != nil {
		Response_Error(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := baselineSocialHttpApplyHeaderUser(r, &req.UserIDHash); err != nil {
		Response_Error(w, http.StatusBadRequest, err.Error())
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
	alias := baselineSocialHttpNormalizeAlias(req.Alias)
	if !Identity_ValidAccountAlias(alias) {
		Response_Error(w, http.StatusBadRequest, "invalid alias")
		return
	}
	if err := s.Store.baselineSocialSetAccountAlias(r.Context(), req.UserIDHash, alias); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			Response_Error(w, http.StatusConflict, "alias unavailable")
			return
		}
		if errors.Is(err, ErrSyncUserNotFound) {
			Response_Error(w, http.StatusNotFound, "sync account not found")
			return
		}
		slog.Error("set account alias", "user", LogSafety_LogText(req.UserIDHash), "error", err)
		Response_Error(w, http.StatusInternalServerError, "alias failed")
		return
	}
	Response_JSON(w, http.StatusOK, AliasResponse{Status: "ok", Alias: alias})
}

func (s *Server) baselineSocialHttpHandleProfileIcon(w http.ResponseWriter, r *http.Request) {
	_, req, err := baselineSocialHttpReadProfileIconRequest(w, r, s.Cfg.MaxBodyBytes)
	if err != nil {
		Response_Error(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := baselineSocialHttpApplyHeaderUser(r, &req.UserIDHash); err != nil {
		Response_Error(w, http.StatusBadRequest, err.Error())
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
	if !baselineSocialHttpValidProfileIcon(req.ProfileIcon) {
		Response_Error(w, http.StatusBadRequest, "invalid profile_icon")
		return
	}
	if err := s.Store.baselineSocialSetAccountProfileIcon(r.Context(), req.UserIDHash, req.ProfileIcon); err != nil {
		if errors.Is(err, ErrSyncUserNotFound) {
			Response_Error(w, http.StatusNotFound, "sync account not found")
			return
		}
		slog.Error("set profile icon", "user", LogSafety_LogText(req.UserIDHash), "error", err)
		Response_Error(w, http.StatusInternalServerError, "profile icon failed")
		return
	}
	Response_JSON(w, http.StatusOK, ProfileIconResponse{Status: "ok", ProfileIcon: req.ProfileIcon})
}

func (s *Server) baselineSocialHttpHandleFriends(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.baselineBearerUser(w, r)
	if !ok {
		return
	}
	friends, err := s.Store.baselineSocialListFriends(r.Context(), userID)
	if err != nil {
		slog.Error("list friends", "user", LogSafety_LogText(userID), "error", err)
		Response_Error(w, http.StatusInternalServerError, "friends failed")
		return
	}
	response := FriendsResponse{Friends: friends}
	s.baselineSocialHttpCacheSocialSnapshot(r.Context(), userID, "friends.list", response)
	Response_JSON(w, http.StatusOK, response)
}

func (s *Server) baselineSocialHttpHandleFriendRoute(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.baselineBearerUser(w, r)
	if !ok {
		return
	}
	friendID := strings.TrimPrefix(r.URL.Path, "/api/v1/friends/")
	friendID = strings.ToLower(strings.Trim(friendID, "/"))
	if !Identity_ValidUserID(friendID) {
		Response_Error(w, http.StatusNotFound, "friend not found")
		return
	}
	if err := s.Store.baselineSocialRemoveFriend(r.Context(), userID, friendID); err != nil {
		slog.Error("remove friend", "user", LogSafety_LogText(userID), "friend", LogSafety_LogText(friendID), "error", err)
		Response_Error(w, http.StatusInternalServerError, "friend remove failed")
		return
	}
	SyncHub_Publish(s.SyncHub, userID, 0)
	SyncHub_Publish(s.SyncHub, friendID, 0)
	Response_JSON(w, http.StatusOK, map[string]string{"status": "removed"})
}

func (s *Server) baselineSocialHttpHandleFriendRequests(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.baselineBearerUser(w, r)
	if !ok {
		return
	}
	incoming, outgoing, err := s.Store.baselineSocialListFriendRequests(r.Context(), userID)
	if err != nil {
		slog.Error("list friend requests", "user", LogSafety_LogText(userID), "error", err)
		Response_Error(w, http.StatusInternalServerError, "friend requests failed")
		return
	}
	response := FriendRequestsResponse{Incoming: incoming, Outgoing: outgoing}
	s.baselineSocialHttpCacheSocialSnapshot(r.Context(), userID, "friends.requests", response)
	Response_JSON(w, http.StatusOK, response)
}

func (s *Server) baselineSocialHttpHandleFriendRequestCreate(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.baselineBearerUser(w, r)
	if !ok {
		return
	}
	req, err := baselineSocialHttpReadFriendRequestCreateRequest(w, r, s.Cfg.MaxBodyBytes)
	if err != nil {
		Response_Error(w, http.StatusBadRequest, err.Error())
		return
	}
	target, found, err := s.Store.baselineSocialResolveAccountRef(r.Context(), req.Target)
	if err != nil {
		slog.Error("resolve friend target", "user", LogSafety_LogText(userID), "error", err)
		Response_Error(w, http.StatusInternalServerError, "friend request failed")
		return
	}
	if !found {
		Response_Error(w, http.StatusNotFound, "friend target not found")
		return
	}
	resource := ResourceId_New()
	id, err := resource.Value, resource.Error
	if err != nil {
		slog.Error("generate friend request id", "error", err)
		Response_Error(w, http.StatusInternalServerError, "friend request failed")
		return
	}
	item, err := s.Store.baselineSocialCreateFriendRequest(r.Context(), id, userID, target)
	if err != nil {
		if strings.Contains(err.Error(), "self") || strings.Contains(err.Error(), "already friends") {
			Response_Error(w, http.StatusConflict, err.Error())
			return
		}
		slog.Error("create friend request", "user", LogSafety_LogText(userID), "target", LogSafety_LogText(target), "error", err)
		Response_Error(w, http.StatusInternalServerError, "friend request failed")
		return
	}
	SyncHub_Publish(s.SyncHub, userID, 0)
	SyncHub_Publish(s.SyncHub, target, 0)
	Response_JSON(w, http.StatusCreated, FriendRequestResponse{Status: "ok", Request: item})
}

func (s *Server) baselineSocialHttpHandleFriendRequestRoute(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.baselineBearerUser(w, r)
	if !ok {
		return
	}
	requestID, action, ok := baselineSocialHttpParseFriendRequestPath(r.URL.Path)
	if !ok {
		Response_Error(w, http.StatusNotFound, "friend request not found")
		return
	}
	var item FriendRequest
	var err error
	switch action {
	case "accept":
		item, err = s.Store.baselineSocialAcceptFriendRequest(r.Context(), userID, requestID)
	case "decline":
		item, err = s.Store.baselineSocialDeclineFriendRequest(r.Context(), userID, requestID)
	default:
		Response_Error(w, http.StatusNotFound, "friend request not found")
		return
	}
	if errors.Is(err, sql.ErrNoRows) {
		Response_Error(w, http.StatusNotFound, "friend request not found")
		return
	}
	if errors.Is(err, ErrSyncUserNotFound) {
		Response_Error(w, http.StatusForbidden, "friend request not owned by user")
		return
	}
	if err != nil {
		if strings.Contains(err.Error(), "not pending") {
			Response_Error(w, http.StatusConflict, err.Error())
			return
		}
		slog.Error("friend request action", "user", LogSafety_LogText(userID), "request", LogSafety_LogText(requestID), "action", LogSafety_LogText(action), "error", err)
		Response_Error(w, http.StatusInternalServerError, "friend request failed")
		return
	}
	SyncHub_Publish(s.SyncHub, item.RequesterUserID, 0)
	SyncHub_Publish(s.SyncHub, item.TargetUserID, 0)
	Response_JSON(w, http.StatusOK, FriendRequestResponse{Status: item.Status, Request: item})
}

func (s *Server) baselineSocialHttpHandleProfileStatsPut(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.baselineBearerUser(w, r)
	if !ok {
		return
	}
	req, err := baselineSocialHttpReadProfileStatsRequest(w, r, s.Cfg.MaxBodyBytes)
	if err != nil {
		Response_Error(w, http.StatusBadRequest, err.Error())
		return
	}
	applied, err := s.Store.baselineSocialUpsertProfileStats(r.Context(), userID, req.App, req.Metrics)
	if err != nil {
		slog.Error("upsert profile stats", "user", LogSafety_LogText(userID), "app", LogSafety_LogText(req.App), "error", err)
		Response_Error(w, http.StatusInternalServerError, "profile stats failed")
		return
	}
	if applied > 0 {
		SyncHub_Publish(s.SyncHub, userID, 0)
		if friends, err := s.Store.baselineSocialListFriends(r.Context(), userID); err == nil {
			for _, friend := range friends {
				SyncHub_Publish(s.SyncHub, friend.UserIDHash, 0)
			}
		} else {
			slog.Error("notify profile stats friends", "user", LogSafety_LogText(userID), "error", err)
		}
	}
	Response_JSON(w, http.StatusOK, ProfileStatsResponse{Status: "ok", Applied: applied})
}

func (s *Server) baselineSocialHttpHandleFriendStats(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.baselineBearerUser(w, r)
	if !ok {
		return
	}
	app := strings.TrimSpace(r.URL.Query().Get("app"))
	practice := strings.TrimSpace(r.URL.Query().Get("practice"))
	metric := strings.TrimSpace(r.URL.Query().Get("metric"))
	if !Identity_ValidNamespace(app) || !Identity_ValidNamespace(practice) || !Identity_ValidNamespace(metric) ||
		!baselineSocialHttpValidLeaderboardMetric(practice, metric) {
		Response_Error(w, http.StatusBadRequest, "invalid stats query")
		return
	}
	rows, err := s.Store.baselineLeaderboardFriendStats(r.Context(), userID, app, practice, metric)
	if err != nil {
		slog.Error("friend stats", "user", LogSafety_LogText(userID), "app", LogSafety_LogText(app), "practice", LogSafety_LogText(practice), "metric", LogSafety_LogText(metric), "error", err)
		Response_Error(w, http.StatusInternalServerError, "friend stats failed")
		return
	}
	response := FriendStatsResponse{Rows: rows}
	s.baselineSocialHttpCacheSocialSnapshot(r.Context(), userID,
		"leaderboard."+app+"."+practice+"."+metric, response)
	Response_JSON(w, http.StatusOK, response)
}

func (s *Server) baselineSocialHttpCacheSocialSnapshot(ctx context.Context, userID, kind string, value any) {
	payload, err := json.Marshal(value)
	if err != nil {
		slog.Error("marshal social cache", "user", LogSafety_LogText(userID), "kind", LogSafety_LogText(kind), "error", err)
		return
	}
	applied, err := s.Store.baselineSnapshotSet(ctx, userID, kind, payload)
	if err != nil {
		slog.Error("write social cache", "user", LogSafety_LogText(userID), "kind", LogSafety_LogText(kind), "error", err)
		return
	}
	if applied > 0 {
		SyncHub_Publish(s.SyncHub, userID, 0)
	}
}

func baselineSocialHttpNormalizeAlias(alias string) string {
	alias = strings.ToLower(strings.TrimSpace(alias))
	alias = strings.TrimPrefix(alias, "@")
	return alias
}

func baselineSocialHttpValidProfileIcon(profileIcon int) bool {
	return profileIcon >= ProfileIconNone && profileIcon <= ProfileIconTree5
}

func baselineSocialHttpValidLeaderboardMetric(practice, metric string) bool {
	switch practice {
	case "whm":
		return metric == "streak" || metric == "avg_hold"
	case "meditation":
		return metric == "streak" || metric == "avg_time"
	case "sun_salutation":
		return metric == "streak"
	default:
		return false
	}
}

func baselineSocialHttpApplyHeaderUser(r *http.Request, bodyUser *string) error {
	userHeader := HttpAuth_UserHeader(r)
	headerUser, headerName := userHeader.Value, userHeader.Name
	if headerUser == "" {
		return errors.New("missing X-Daochi-User")
	}
	if *bodyUser == "" {
		*bodyUser = headerUser
		return nil
	}
	*bodyUser = strings.ToLower(strings.TrimSpace(*bodyUser))
	if *bodyUser != headerUser {
		return errors.New(headerName + " does not match user_id_hash")
	}
	return nil
}

func baselineSocialHttpReadAliasRequest(w http.ResponseWriter, r *http.Request, maxBody int64) ([]byte, AliasRequest, error) {
	var req AliasRequest
	bodyResult := HttpBody_ReadJSON(w, r, maxBody)
	body, err := bodyResult.Value, bodyResult.Error
	if err != nil {
		return nil, req, err
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, req, errors.New("invalid json")
	}
	req.UserIDHash = strings.ToLower(strings.TrimSpace(req.UserIDHash))
	req.Alias = baselineSocialHttpNormalizeAlias(req.Alias)
	return body, req, nil
}

func baselineSocialHttpReadProfileIconRequest(w http.ResponseWriter, r *http.Request, maxBody int64) ([]byte, ProfileIconRequest, error) {
	var req ProfileIconRequest
	bodyResult := HttpBody_ReadJSON(w, r, maxBody)
	body, err := bodyResult.Value, bodyResult.Error
	if err != nil {
		return nil, req, err
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, req, errors.New("invalid json")
	}
	req.UserIDHash = strings.ToLower(strings.TrimSpace(req.UserIDHash))
	return body, req, nil
}

func baselineSocialHttpReadFriendRequestCreateRequest(w http.ResponseWriter, r *http.Request, maxBody int64) (FriendRequestCreateRequest, error) {
	var req FriendRequestCreateRequest
	bodyResult := HttpBody_ReadJSON(w, r, maxBody)
	body, err := bodyResult.Value, bodyResult.Error
	if err != nil {
		return req, err
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return req, errors.New("invalid json")
	}
	req.Target = strings.TrimSpace(req.Target)
	if req.Target == "" {
		return req, errors.New("target required")
	}
	return req, nil
}

func baselineSocialHttpReadProfileStatsRequest(w http.ResponseWriter, r *http.Request, maxBody int64) (ProfileStatsRequest, error) {
	var req ProfileStatsRequest
	bodyResult := HttpBody_ReadJSON(w, r, maxBody)
	body, err := bodyResult.Value, bodyResult.Error
	if err != nil {
		return req, err
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return req, errors.New("invalid json")
	}
	req.App = strings.TrimSpace(req.App)
	if !Identity_ValidNamespace(req.App) {
		return req, errors.New("invalid app")
	}
	if len(req.Metrics) > 100 {
		return req, errors.New("too many metrics")
	}
	for i := range req.Metrics {
		req.Metrics[i].Practice = strings.TrimSpace(req.Metrics[i].Practice)
		req.Metrics[i].Metric = strings.TrimSpace(req.Metrics[i].Metric)
		req.Metrics[i].Label = strings.TrimSpace(req.Metrics[i].Label)
		if !Identity_ValidNamespace(req.Metrics[i].Practice) || !Identity_ValidNamespace(req.Metrics[i].Metric) {
			return req, errors.New("invalid metric")
		}
	}
	return req, nil
}

func baselineSocialHttpParseFriendRequestPath(path string) (requestID string, action string, ok bool) {
	const prefix = "/api/v1/friends/requests/"
	rest := strings.TrimPrefix(path, prefix)
	if rest == path || rest == "" {
		return "", "", false
	}
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) == 2 && Identity_ValidResourceID(parts[0]) && (parts[1] == "accept" || parts[1] == "decline") {
		return parts[0], parts[1], true
	}
	return "", "", false
}
