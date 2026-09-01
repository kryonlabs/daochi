package main

import "context"

func (s *Store) SeedTokenAssets(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO token_assets(issuer_id,asset_id,display_name,decimals,status)
VALUES('waozi','waozi:token','Chi',6,'active')
ON CONFLICT(asset_id) DO UPDATE SET
	issuer_id=excluded.issuer_id,
	display_name=excluded.display_name,
	decimals=excluded.decimals,
	status=excluded.status,
	updated_at=CURRENT_TIMESTAMP`)
	return err
}
