package discovery

import "pmeq/internal/scmpstock"

// BindInventoryParty is invoked only after the v3 ticket and role stock have
// been independently authenticated. Legacy packets cannot acquire a stock.
func BindInventoryParty(p *PartyPacket, s *Static, pool *scmpstock.Pool) error {
	if p == nil || s == nil || pool == nil || !p.inventoryV3 || p.stock != nil || p.party != s.party || pool.Role != p.party || pool.Manifest.BankID != p.bankID || pool.Manifest.IndexID != s.target.Lineage().IndexID || pool.Manifest.LayoutID != s.target.Lineage().LayoutID || pool.Manifest.Bin != p.position.Bin() || pool.Manifest.MaxPosition != p.position.MaxPosition() {
		return ErrBinding
	}
	if s.productionSeal != [32]byte{} && pool.Manifest.IndexSeal != s.productionSeal {
		return ErrBinding
	}
	p.stock = pool
	return nil
}
