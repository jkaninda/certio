package store

import (
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ACMERepo persists everything the ACME server needs.
type ACMERepo struct{ db *gorm.DB }

// --- accounts ---

// CreateAccount registers an account.
func (r *ACMERepo) CreateAccount(a *ACMEAccount) error { return translate(r.db.Create(a).Error) }

// UpdateAccount saves an account.
func (r *ACMERepo) UpdateAccount(a *ACMEAccount) error { return translate(r.db.Save(a).Error) }

// GetAccount loads an account by ID.
func (r *ACMERepo) GetAccount(id string) (*ACMEAccount, error) {
	var a ACMEAccount
	if err := r.db.First(&a, "id = ?", id).Error; err != nil {
		return nil, translate(err)
	}
	return &a, nil
}

// AccountByThumbprint finds the account a key already belongs to. RFC 8555
// requires newAccount with a known key to return the existing account rather
// than quietly create a second one.
func (r *ACMERepo) AccountByThumbprint(thumbprint string) (*ACMEAccount, error) {
	var a ACMEAccount
	if err := r.db.First(&a, "key_thumbprint = ?", thumbprint).Error; err != nil {
		return nil, translate(err)
	}
	return &a, nil
}

// ListAccounts returns every account, newest first.
func (r *ACMERepo) ListAccounts(p Pagination) (Page[ACMEAccount], error) {
	p.Normalize()
	q := r.db.Model(&ACMEAccount{})

	var total int64
	if err := q.Count(&total).Error; err != nil {
		return Page[ACMEAccount]{}, translate(err)
	}
	var items []ACMEAccount
	if err := q.Order("created_at DESC").Limit(p.Limit).Offset(p.Offset()).Find(&items).Error; err != nil {
		return Page[ACMEAccount]{}, translate(err)
	}
	return newPage(items, total, p), nil
}

// TouchAccount records that an account made a request.
func (r *ACMERepo) TouchAccount(id string) error {
	now := time.Now().UTC()
	return translate(r.db.Model(&ACMEAccount{}).Where("id = ?", id).
		Update("last_used_at", now).Error)
}

// --- external account bindings ---

// CreateExternalAccount issues a binding credential.
func (r *ACMERepo) CreateExternalAccount(e *ACMEExternalAccount) error {
	return translate(r.db.Create(e).Error)
}

// UpdateExternalAccount saves a binding credential.
func (r *ACMERepo) UpdateExternalAccount(e *ACMEExternalAccount) error {
	return translate(r.db.Save(e).Error)
}

// ExternalAccountByKID looks a binding up by the identifier the client sends.
func (r *ACMERepo) ExternalAccountByKID(kid string) (*ACMEExternalAccount, error) {
	var e ACMEExternalAccount
	if err := r.db.First(&e, "kid = ?", kid).Error; err != nil {
		return nil, translate(err)
	}
	return &e, nil
}

// GetExternalAccount loads a binding by ID.
func (r *ACMERepo) GetExternalAccount(id string) (*ACMEExternalAccount, error) {
	var e ACMEExternalAccount
	if err := r.db.First(&e, "id = ?", id).Error; err != nil {
		return nil, translate(err)
	}
	return &e, nil
}

// ListExternalAccounts returns every binding, newest first.
func (r *ACMERepo) ListExternalAccounts() ([]ACMEExternalAccount, error) {
	var items []ACMEExternalAccount
	err := r.db.Order("created_at DESC").Find(&items).Error
	return items, translate(err)
}

// DeleteExternalAccount removes a binding. Accounts already registered with it
// keep working: revoking the credential stops new registrations, and
// deactivating those accounts is a separate, deliberate act.
func (r *ACMERepo) DeleteExternalAccount(id string) error {
	res := r.db.Delete(&ACMEExternalAccount{}, "id = ?", id)
	if res.Error != nil {
		return translate(res.Error)
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// --- orders ---

// CreateOrder inserts an order.
func (r *ACMERepo) CreateOrder(o *ACMEOrder) error { return translate(r.db.Create(o).Error) }

// UpdateOrder saves an order.
func (r *ACMERepo) UpdateOrder(o *ACMEOrder) error { return translate(r.db.Save(o).Error) }

// GetOrder loads an order by ID.
func (r *ACMERepo) GetOrder(id string) (*ACMEOrder, error) {
	var o ACMEOrder
	if err := r.db.First(&o, "id = ?", id).Error; err != nil {
		return nil, translate(err)
	}
	return &o, nil
}

// OrdersByAccount returns an account's orders, newest first.
func (r *ACMERepo) OrdersByAccount(accountID string, limit int) ([]ACMEOrder, error) {
	if limit <= 0 {
		limit = 100
	}
	var items []ACMEOrder
	err := r.db.Where("account_id = ?", accountID).
		Order("created_at DESC").Limit(limit).Find(&items).Error
	return items, translate(err)
}

// --- authorizations and challenges ---

// CreateAuthorization inserts an authorization.
func (r *ACMERepo) CreateAuthorization(a *ACMEAuthorization) error {
	return translate(r.db.Create(a).Error)
}

// UpdateAuthorization saves an authorization.
func (r *ACMERepo) UpdateAuthorization(a *ACMEAuthorization) error {
	return translate(r.db.Save(a).Error)
}

// GetAuthorization loads an authorization by ID.
func (r *ACMERepo) GetAuthorization(id string) (*ACMEAuthorization, error) {
	var a ACMEAuthorization
	if err := r.db.First(&a, "id = ?", id).Error; err != nil {
		return nil, translate(err)
	}
	return &a, nil
}

// AuthorizationsByOrder returns an order's authorizations in creation order,
// so the list a client polls stays stable.
func (r *ACMERepo) AuthorizationsByOrder(orderID string) ([]ACMEAuthorization, error) {
	var items []ACMEAuthorization
	err := r.db.Where("order_id = ?", orderID).Order("created_at ASC").Find(&items).Error
	return items, translate(err)
}

// CreateChallenge inserts a challenge.
func (r *ACMERepo) CreateChallenge(c *ACMEChallenge) error { return translate(r.db.Create(c).Error) }

// UpdateChallenge saves a challenge.
func (r *ACMERepo) UpdateChallenge(c *ACMEChallenge) error { return translate(r.db.Save(c).Error) }

// GetChallenge loads a challenge by ID.
func (r *ACMERepo) GetChallenge(id string) (*ACMEChallenge, error) {
	var c ACMEChallenge
	if err := r.db.First(&c, "id = ?", id).Error; err != nil {
		return nil, translate(err)
	}
	return &c, nil
}

// ChallengesByAuthorization returns an authorization's challenges.
func (r *ACMERepo) ChallengesByAuthorization(authorizationID string) ([]ACMEChallenge, error) {
	var items []ACMEChallenge
	err := r.db.Where("authorization_id = ?", authorizationID).
		Order("created_at ASC").Find(&items).Error
	return items, translate(err)
}

// --- nonces ---

// IssueNonce records a freshly minted nonce.
func (r *ACMERepo) IssueNonce(value string, ttl time.Duration) error {
	now := time.Now().UTC()
	return translate(r.db.Clauses(clause.OnConflict{DoNothing: true}).
		Create(&ACMENonce{Value: value, IssuedAt: now, ExpiresAt: now.Add(ttl)}).Error)
}

// SpendNonce consumes a nonce, reporting whether it was valid.
//
// The delete is the check: a conditional read followed by a delete would let
// two concurrent replays of the same request both see it as unspent, which is
// precisely what a nonce exists to prevent.
func (r *ACMERepo) SpendNonce(value string) (bool, error) {
	res := r.db.Where("value = ? AND expires_at > ?", value, time.Now().UTC()).
		Delete(&ACMENonce{})
	if res.Error != nil {
		return false, translate(res.Error)
	}
	return res.RowsAffected > 0, nil
}

// PruneNonces drops expired nonces.
func (r *ACMERepo) PruneNonces(before time.Time) (int64, error) {
	res := r.db.Where("expires_at < ?", before.UTC()).Delete(&ACMENonce{})
	return res.RowsAffected, translate(res.Error)
}

// PruneOrders drops orders and their authorizations once they have expired,
// along with the challenges hanging off them.
func (r *ACMERepo) PruneOrders(before time.Time) (int64, error) {
	var removed int64
	err := r.db.Transaction(func(tx *gorm.DB) error {
		var stale []ACMEOrder
		if err := tx.Where("expires_at < ?", before.UTC()).Find(&stale).Error; err != nil {
			return err
		}
		for i := range stale {
			var authzs []ACMEAuthorization
			if err := tx.Where("order_id = ?", stale[i].ID).Find(&authzs).Error; err != nil {
				return err
			}
			for j := range authzs {
				if err := tx.Where("authorization_id = ?", authzs[j].ID).
					Delete(&ACMEChallenge{}).Error; err != nil {
					return err
				}
			}
			if err := tx.Where("order_id = ?", stale[i].ID).Delete(&ACMEAuthorization{}).Error; err != nil {
				return err
			}
		}
		res := tx.Where("expires_at < ?", before.UTC()).Delete(&ACMEOrder{})
		removed = res.RowsAffected
		return res.Error
	})
	return removed, translate(err)
}
