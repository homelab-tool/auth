package service

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

type Group struct {
	ID          int64
	Name        string
	Description string
	IsAdmin     bool
	CreatedAt   string
}

type GroupService struct {
	db *sql.DB
}

func NewGroupService(db *sql.DB) *GroupService {
	return &GroupService{db: db}
}

func (s *GroupService) EnsureAdminGroup(ctx context.Context) (int64, error) {
	_, err := s.db.ExecContext(ctx,
		"INSERT OR IGNORE INTO groups (name, description, is_admin) VALUES ('Admin', 'Administrators', 1)")
	if err != nil {
		return 0, fmt.Errorf("failed to ensure admin group: %w", err)
	}

	var id int64
	err = s.db.QueryRowContext(ctx, "SELECT id FROM groups WHERE name = 'Admin'").Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("failed to get admin group id: %w", err)
	}
	return id, nil
}

func (s *GroupService) Create(ctx context.Context, name, description string, isAdmin bool) (*Group, error) {
	result, err := s.db.ExecContext(ctx,
		"INSERT INTO groups (name, description, is_admin) VALUES (?, ?, ?)",
		name, description, isAdmin)
	if err != nil {
		return nil, fmt.Errorf("failed to create group: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("failed to get last insert id: %w", err)
	}

	group, err := s.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	return group, nil
}

func (s *GroupService) List(ctx context.Context) ([]Group, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT id, name, description, is_admin, created_at FROM groups ORDER BY name")
	if err != nil {
		return nil, fmt.Errorf("failed to list groups: %w", err)
	}
	defer rows.Close()

	var groups []Group
	for rows.Next() {
		var g Group
		if err := rows.Scan(&g.ID, &g.Name, &g.Description, &g.IsAdmin, &g.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan group: %w", err)
		}
		groups = append(groups, g)
	}
	return groups, rows.Err()
}

func (s *GroupService) GetByID(ctx context.Context, id int64) (*Group, error) {
	var g Group
	err := s.db.QueryRowContext(ctx,
		"SELECT id, name, description, is_admin, created_at FROM groups WHERE id = ?", id).
		Scan(&g.ID, &g.Name, &g.Description, &g.IsAdmin, &g.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("failed to get group: %w", err)
	}
	return &g, nil
}

func (s *GroupService) Delete(ctx context.Context, id int64) error {
	group, err := s.GetByID(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to get group: %w", err)
	}

	if group.IsAdmin {
		var count int
		err = s.db.QueryRowContext(ctx,
			"SELECT COUNT(*) FROM groups WHERE is_admin = 1").Scan(&count)
		if err != nil {
			return fmt.Errorf("failed to count admin groups: %w", err)
		}
		if count <= 1 {
			return fmt.Errorf("cannot delete the last admin group")
		}
	}

	_, err = s.db.ExecContext(ctx, "DELETE FROM groups WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("failed to delete group: %w", err)
	}
	return nil
}

func (s *GroupService) AddUser(ctx context.Context, userID, groupID int64) error {
	_, err := s.db.ExecContext(ctx,
		"INSERT INTO user_groups (user_id, group_id) VALUES (?, ?)",
		userID, groupID)
	if err != nil {
		return fmt.Errorf("failed to add user to group: %w", err)
	}
	return nil
}

func (s *GroupService) RemoveUser(ctx context.Context, userID, groupID int64) error {
	group, err := s.GetByID(ctx, groupID)
	if err != nil {
		return fmt.Errorf("failed to get group: %w", err)
	}

	if group.IsAdmin {
		var remaining int
		err = s.db.QueryRowContext(ctx, `
			SELECT COUNT(*) FROM user_groups ug
			JOIN groups g ON ug.group_id = g.id
			WHERE ug.user_id = ? AND g.is_admin = 1 AND ug.group_id != ?
		`, userID, groupID).Scan(&remaining)
		if err != nil {
			return fmt.Errorf("failed to count admin groups: %w", err)
		}
		if remaining == 0 {
			return fmt.Errorf("cannot remove user from their only admin group")
		}
	}

	_, err = s.db.ExecContext(ctx,
		"DELETE FROM user_groups WHERE user_id = ? AND group_id = ?",
		userID, groupID)
	if err != nil {
		return fmt.Errorf("failed to remove user from group: %w", err)
	}
	return nil
}

func (s *GroupService) UsersInGroup(ctx context.Context, groupID int64) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT u.id, u.display_name, u.created_at FROM users u
		JOIN user_groups ug ON u.id = ug.user_id
		WHERE ug.group_id = ?
		ORDER BY u.display_name
	`, groupID)
	if err != nil {
		return nil, fmt.Errorf("failed to list users in group: %w", err)
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.DisplayName, &u.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan user: %w", err)
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

func (s *GroupService) GroupsForUser(ctx context.Context, userID int64) ([]Group, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT g.id, g.name, g.description, g.is_admin, g.created_at FROM groups g
		JOIN user_groups ug ON g.id = ug.group_id
		WHERE ug.user_id = ?
		ORDER BY g.name
	`, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to list groups for user: %w", err)
	}
	defer rows.Close()

	var groups []Group
	for rows.Next() {
		var g Group
		if err := rows.Scan(&g.ID, &g.Name, &g.Description, &g.IsAdmin, &g.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan group: %w", err)
		}
		groups = append(groups, g)
	}
	return groups, rows.Err()
}

func (s *GroupService) IsAdmin(ctx context.Context, userID int64) (bool, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM user_groups ug
		JOIN groups g ON ug.group_id = g.id
		WHERE ug.user_id = ? AND g.is_admin = 1
	`, userID).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to check admin status: %w", err)
	}
	return count > 0, nil
}

func (s *GroupService) MemberCount(ctx context.Context, groupID int64) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM user_groups WHERE group_id = ?", groupID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count members: %w", err)
	}
	return count, nil
}

func (s *GroupService) GrantGroupSiteAccess(ctx context.Context, groupID, siteConfigID int64) error {
	_, err := s.db.ExecContext(ctx,
		"INSERT INTO group_site_access (group_id, site_config_id) VALUES (?, ?)",
		groupID, siteConfigID)
	if err != nil {
		return fmt.Errorf("failed to grant group site access: %w", err)
	}
	return nil
}

func (s *GroupService) RevokeGroupSiteAccess(ctx context.Context, groupID, siteConfigID int64) error {
	_, err := s.db.ExecContext(ctx,
		"DELETE FROM group_site_access WHERE group_id = ? AND site_config_id = ?",
		groupID, siteConfigID)
	if err != nil {
		return fmt.Errorf("failed to revoke group site access: %w", err)
	}
	return nil
}

func (s *GroupService) SitesForGroup(ctx context.Context, groupID int64) ([]SiteConfig, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT sc.id, sc.hostname, sc.created_at, sc.updated_at FROM site_configs sc
		JOIN group_site_access gsa ON sc.id = gsa.site_config_id
		WHERE gsa.group_id = ?
		ORDER BY sc.hostname
	`, groupID)
	if err != nil {
		return nil, fmt.Errorf("failed to list sites for group: %w", err)
	}
	defer rows.Close()

	var sites []SiteConfig
	for rows.Next() {
		var sc SiteConfig
		var createdAt, updatedAt string
		if err := rows.Scan(&sc.ID, &sc.Hostname, &createdAt, &updatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan site config: %w", err)
		}
		sc.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		sc.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)
		sites = append(sites, sc)
	}
	return sites, rows.Err()
}

func (s *GroupService) GrantUserSiteAccess(ctx context.Context, userID, siteConfigID int64) error {
	_, err := s.db.ExecContext(ctx,
		"INSERT INTO user_site_access (user_id, site_config_id) VALUES (?, ?)",
		userID, siteConfigID)
	if err != nil {
		return fmt.Errorf("failed to grant user site access: %w", err)
	}
	return nil
}

func (s *GroupService) RevokeUserSiteAccess(ctx context.Context, userID, siteConfigID int64) error {
	_, err := s.db.ExecContext(ctx,
		"DELETE FROM user_site_access WHERE user_id = ? AND site_config_id = ?",
		userID, siteConfigID)
	if err != nil {
		return fmt.Errorf("failed to revoke user site access: %w", err)
	}
	return nil
}

func (s *GroupService) UsersForSite(ctx context.Context, siteConfigID int64) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT u.id, u.display_name, u.created_at FROM users u
		JOIN user_site_access usa ON u.id = usa.user_id
		WHERE usa.site_config_id = ?
		ORDER BY u.display_name
	`, siteConfigID)
	if err != nil {
		return nil, fmt.Errorf("failed to list users for site: %w", err)
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.DisplayName, &u.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan user: %w", err)
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

func (s *GroupService) GroupsForSite(ctx context.Context, siteConfigID int64) ([]Group, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT g.id, g.name, g.description, g.is_admin, g.created_at FROM groups g
		JOIN group_site_access gsa ON g.id = gsa.group_id
		WHERE gsa.site_config_id = ?
		ORDER BY g.name
	`, siteConfigID)
	if err != nil {
		return nil, fmt.Errorf("failed to list groups for site: %w", err)
	}
	defer rows.Close()

	var groups []Group
	for rows.Next() {
		var g Group
		if err := rows.Scan(&g.ID, &g.Name, &g.Description, &g.IsAdmin, &g.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan group: %w", err)
		}
		groups = append(groups, g)
	}
	return groups, rows.Err()
}

func (s *GroupService) CanAccessSite(ctx context.Context, userID, siteConfigID int64) (bool, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM (
			SELECT 1 FROM user_site_access WHERE user_id = ? AND site_config_id = ?
			UNION
			SELECT 1 FROM user_groups ug
			JOIN group_site_access gsa ON ug.group_id = gsa.group_id
			WHERE ug.user_id = ? AND gsa.site_config_id = ?
		)
	`, userID, siteConfigID, userID, siteConfigID).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to check site access: %w", err)
	}
	return count > 0, nil
}
