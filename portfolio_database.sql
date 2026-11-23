-- ============================================================================
-- PORTFOLIO APPLICATION DATABASE
-- PostgreSQL 14+ recommended
-- Schemas: auth, portfolio, audit
-- Run this script once against an empty database.
-- Example database name: portfolio_db
-- ============================================================================

BEGIN;

-- 1. SCHEMAS -----------------------------------------------------------------
CREATE SCHEMA IF NOT EXISTS auth;
CREATE SCHEMA IF NOT EXISTS portfolio;
CREATE SCHEMA IF NOT EXISTS audit;

-- 2. COMMON updated_at TRIGGER FUNCTION -------------------------------------
CREATE OR REPLACE FUNCTION public.set_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$;

-- 3. AUTHENTICATION AND AUTHORIZATION ---------------------------------------

-- A user account is separate from the role approval process.
CREATE TABLE auth.users (
    user_id             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    first_name          VARCHAR(100) NOT NULL,
    middle_name         VARCHAR(100),
    last_name           VARCHAR(100),
    mobile              VARCHAR(20),
    email               VARCHAR(255) NOT NULL,
    password_hash       VARCHAR(255) NOT NULL,
    email_verified_at   TIMESTAMPTZ,
    account_status      VARCHAR(20) NOT NULL DEFAULT 'ACTIVE'
                        CHECK (account_status IN ('ACTIVE', 'DISABLED', 'LOCKED')),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by          BIGINT,
    updated_by          BIGINT,
    CONSTRAINT uq_users_email UNIQUE (email)
);

-- Case-insensitive uniqueness as an additional safeguard.
CREATE UNIQUE INDEX uq_users_email_lower ON auth.users (LOWER(email));
CREATE INDEX idx_users_account_status ON auth.users (account_status);

CREATE TABLE auth.roles (
    role_id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    role_name       VARCHAR(50) NOT NULL UNIQUE,
    description     VARCHAR(255),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE auth.permissions (
    permission_id   BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    permission_key  VARCHAR(100) NOT NULL UNIQUE,
    description     VARCHAR(255),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE auth.role_permissions (
    role_id         BIGINT NOT NULL REFERENCES auth.roles(role_id) ON DELETE CASCADE,
    permission_id   BIGINT NOT NULL REFERENCES auth.permissions(permission_id) ON DELETE CASCADE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE auth.user_roles (
    user_role_id       BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id            BIGINT NOT NULL REFERENCES auth.users(user_id) ON DELETE CASCADE,
    role_id            BIGINT NOT NULL REFERENCES auth.roles(role_id) ON DELETE RESTRICT,
    approval_status    VARCHAR(20) NOT NULL DEFAULT 'PENDING'
                       CHECK (approval_status IN ('PENDING', 'APPROVED', 'REJECTED')),
    requested_at       TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    approved_by        BIGINT REFERENCES auth.users(user_id) ON DELETE SET NULL,
    approved_at        TIMESTAMPTZ,
    rejection_reason   TEXT,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_by         BIGINT REFERENCES auth.users(user_id) ON DELETE SET NULL,
    CONSTRAINT uq_user_role UNIQUE (user_id, role_id),
    CONSTRAINT chk_role_approval_metadata CHECK (
        (approval_status = 'APPROVED' AND approved_at IS NOT NULL)
        OR approval_status <> 'APPROVED'
    )
);
CREATE INDEX idx_user_roles_user_id ON auth.user_roles(user_id);
CREATE INDEX idx_user_roles_approval_status ON auth.user_roles(approval_status);

-- Store only a hash of the one-time email verification token.
CREATE TABLE auth.email_verification_tokens (
    token_id       BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id        BIGINT NOT NULL REFERENCES auth.users(user_id) ON DELETE CASCADE,
    token_hash     VARCHAR(255) NOT NULL UNIQUE,
    expires_at     TIMESTAMPTZ NOT NULL,
    used_at        TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_email_tokens_user_id ON auth.email_verification_tokens(user_id);
CREATE INDEX idx_email_tokens_expires_at ON auth.email_verification_tokens(expires_at);

-- Store only a hash of refresh tokens. Access JWTs generally remain short-lived
-- and are not stored in this table.
CREATE TABLE auth.refresh_tokens (
    refresh_token_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id          BIGINT NOT NULL REFERENCES auth.users(user_id) ON DELETE CASCADE,
    token_hash       VARCHAR(255) NOT NULL UNIQUE,
    expires_at       TIMESTAMPTZ NOT NULL,
    revoked_at       TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_refresh_tokens_user_id ON auth.refresh_tokens(user_id);

-- Add self-referencing audit FKs after auth.users exists.
ALTER TABLE auth.users
    ADD CONSTRAINT fk_users_created_by FOREIGN KEY (created_by)
        REFERENCES auth.users(user_id) ON DELETE SET NULL,
    ADD CONSTRAINT fk_users_updated_by FOREIGN KEY (updated_by)
        REFERENCES auth.users(user_id) ON DELETE SET NULL;

-- 4. PORTFOLIO MEDIA --------------------------------------------------------
-- Store metadata and object keys/URLs here, not image binary data.
-- LOCAL: local development storage; S3: AWS S3; EXTERNAL: placeholder/external URL.
CREATE TABLE portfolio.media_assets (
    media_id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    file_name         VARCHAR(255) NOT NULL,
    file_key          VARCHAR(500),
    file_url          TEXT,
    file_type         VARCHAR(30) NOT NULL
                      CHECK (file_type IN ('IMAGE', 'PDF', 'DOCUMENT', 'VIDEO', 'OTHER')),
    mime_type         VARCHAR(150),
    file_size         BIGINT CHECK (file_size IS NULL OR file_size >= 0),
    storage_provider  VARCHAR(20) NOT NULL DEFAULT 'EXTERNAL'
                      CHECK (storage_provider IN ('LOCAL', 'S3', 'EXTERNAL')),
    alt_text          VARCHAR(255),
    is_active         BOOLEAN NOT NULL DEFAULT TRUE,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    uploaded_by       BIGINT REFERENCES auth.users(user_id) ON DELETE SET NULL,
    CONSTRAINT chk_media_location CHECK (file_key IS NOT NULL OR file_url IS NOT NULL)
);
CREATE INDEX idx_media_assets_provider ON portfolio.media_assets(storage_provider);
CREATE INDEX idx_media_assets_active ON portfolio.media_assets(is_active);

-- 5. PORTFOLIO PROFILE ------------------------------------------------------
CREATE TABLE portfolio.profile (
    profile_id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    full_name           VARCHAR(200) NOT NULL,
    professional_title  VARCHAR(200),
    email               VARCHAR(255),
    phone               VARCHAR(30),
    location            VARCHAR(255),
    short_description   TEXT,
    profile_image_id    BIGINT REFERENCES portfolio.media_assets(media_id) ON DELETE SET NULL,
    resume_media_id     BIGINT REFERENCES portfolio.media_assets(media_id) ON DELETE SET NULL,
    is_active           BOOLEAN NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by          BIGINT REFERENCES auth.users(user_id) ON DELETE SET NULL,
    updated_by          BIGINT REFERENCES auth.users(user_id) ON DELETE SET NULL
);

CREATE TABLE portfolio.about_content (
    about_id        BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    profile_id      BIGINT NOT NULL REFERENCES portfolio.profile(profile_id) ON DELETE CASCADE,
    title           VARCHAR(200) NOT NULL,
    description     TEXT NOT NULL,
    display_order   INTEGER NOT NULL DEFAULT 0,
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by      BIGINT REFERENCES auth.users(user_id) ON DELETE SET NULL,
    updated_by      BIGINT REFERENCES auth.users(user_id) ON DELETE SET NULL
);
CREATE INDEX idx_about_profile_active_order ON portfolio.about_content(profile_id, is_active, display_order);

-- 6. PROJECTS AND TECHNOLOGIES ----------------------------------------------
CREATE TABLE portfolio.projects (
    project_id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    profile_id          BIGINT NOT NULL REFERENCES portfolio.profile(profile_id) ON DELETE CASCADE,
    title               VARCHAR(255) NOT NULL,
    description         TEXT,
   problem_statement   TEXT,
   solution_summary    TEXT,
   impact_summary      TEXT,
    start_date          DATE,
    end_date            DATE,
    project_url         TEXT,
    github_url          TEXT,
    
    thumbnail_media_id  BIGINT REFERENCES portfolio.media_assets(media_id) ON DELETE SET NULL,
    is_featured         BOOLEAN NOT NULL DEFAULT FALSE,
    is_active           BOOLEAN NOT NULL DEFAULT TRUE,
    display_order       INTEGER NOT NULL DEFAULT 0,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by          BIGINT REFERENCES auth.users(user_id) ON DELETE SET NULL,
    updated_by          BIGINT REFERENCES auth.users(user_id) ON DELETE SET NULL,
    CONSTRAINT chk_project_dates CHECK (end_date IS NULL OR start_date IS NULL OR end_date >= start_date)
);
CREATE INDEX idx_projects_profile_active_order ON portfolio.projects(profile_id, is_active, display_order);
CREATE INDEX idx_projects_featured ON portfolio.projects(is_featured) WHERE is_featured = TRUE;

CREATE TABLE portfolio.project_impact_metrics (
    impact_metric_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    project_id       BIGINT NOT NULL
                     REFERENCES portfolio.projects(project_id)
                     ON DELETE CASCADE,

    metric_label     VARCHAR(150) NOT NULL,
    metric_value     VARCHAR(100) NOT NULL,
    metric_unit      VARCHAR(50),
    description      TEXT,

    display_order    INTEGER NOT NULL DEFAULT 0,
    is_active        BOOLEAN NOT NULL DEFAULT TRUE,

    created_at       TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    created_by       BIGINT REFERENCES auth.users(user_id) ON DELETE SET NULL,
    updated_by       BIGINT REFERENCES auth.users(user_id) ON DELETE SET NULL
);

CREATE INDEX idx_project_impact_project_order
    ON portfolio.project_impact_metrics
    (project_id, is_active, display_order);

CREATE TABLE portfolio.project_media (
    project_media_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    project_id       BIGINT NOT NULL REFERENCES portfolio.projects(project_id) ON DELETE CASCADE,
    media_id         BIGINT NOT NULL REFERENCES portfolio.media_assets(media_id) ON DELETE RESTRICT,
    caption          VARCHAR(255),
    display_order    INTEGER NOT NULL DEFAULT 0,
    is_active        BOOLEAN NOT NULL DEFAULT TRUE,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by       BIGINT REFERENCES auth.users(user_id) ON DELETE SET NULL,
    CONSTRAINT uq_project_media UNIQUE(project_id, media_id)
);
CREATE INDEX idx_project_media_project_order ON portfolio.project_media(project_id, is_active, display_order);

CREATE TABLE portfolio.technologies (
    technology_id    BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    technology_name  VARCHAR(100) NOT NULL UNIQUE,
    technology_type  VARCHAR(50),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE portfolio.project_technologies (
    project_id     BIGINT NOT NULL REFERENCES portfolio.projects(project_id) ON DELETE CASCADE,
    technology_id  BIGINT NOT NULL REFERENCES portfolio.technologies(technology_id) ON DELETE RESTRICT,
    PRIMARY KEY (project_id, technology_id)
);

-- 7. SKILLS -----------------------------------------------------------------
CREATE TABLE portfolio.skill_categories (
    skill_category_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    category_name     VARCHAR(100) NOT NULL UNIQUE,
    display_order     INTEGER NOT NULL DEFAULT 0,
    is_active         BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE portfolio.skills (
    skill_id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    profile_id         BIGINT NOT NULL REFERENCES portfolio.profile(profile_id) ON DELETE CASCADE,
    skill_category_id  BIGINT REFERENCES portfolio.skill_categories(skill_category_id) ON DELETE SET NULL,
    skill_name         VARCHAR(150) NOT NULL,
    proficiency_level  SMALLINT CHECK (proficiency_level BETWEEN 1 AND 5),
    years_experience   NUMERIC(4,1) CHECK (years_experience IS NULL OR years_experience >= 0),
    display_order      INTEGER NOT NULL DEFAULT 0,
    is_active          BOOLEAN NOT NULL DEFAULT TRUE,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by         BIGINT REFERENCES auth.users(user_id) ON DELETE SET NULL,
    updated_by         BIGINT REFERENCES auth.users(user_id) ON DELETE SET NULL
);
CREATE INDEX idx_skills_profile_active_order ON portfolio.skills(profile_id, is_active, display_order);

-- 8. EDUCATION AND EMPLOYMENT -----------------------------------------------
CREATE TABLE portfolio.education (
    education_id       BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    profile_id         BIGINT NOT NULL REFERENCES portfolio.profile(profile_id) ON DELETE CASCADE,
    institution_name   VARCHAR(255) NOT NULL,
    degree             VARCHAR(200),
    field_of_study     VARCHAR(200),
    start_date         DATE,
    end_date           DATE,
    grade              VARCHAR(50),
    description        TEXT,
    certificate_media_id BIGINT REFERENCES portfolio.media_assets(media_id) ON DELETE SET NULL,
    display_order      INTEGER NOT NULL DEFAULT 0,
    is_active          BOOLEAN NOT NULL DEFAULT TRUE,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by         BIGINT REFERENCES auth.users(user_id) ON DELETE SET NULL,
    updated_by         BIGINT REFERENCES auth.users(user_id) ON DELETE SET NULL,
    CONSTRAINT chk_education_dates CHECK (end_date IS NULL OR start_date IS NULL OR end_date >= start_date)
);
CREATE INDEX idx_education_profile_active_order ON portfolio.education(profile_id, is_active, display_order);

CREATE TABLE portfolio.companies (
    company_id     BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    company_name   VARCHAR(255) NOT NULL,
    website        TEXT,
    logo_media_id  BIGINT REFERENCES portfolio.media_assets(media_id) ON DELETE SET NULL,
    location       VARCHAR(255),
    description    TEXT,
    is_active      BOOLEAN NOT NULL DEFAULT TRUE,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by     BIGINT REFERENCES auth.users(user_id) ON DELETE SET NULL,
    updated_by     BIGINT REFERENCES auth.users(user_id) ON DELETE SET NULL
);
CREATE INDEX idx_companies_name ON portfolio.companies(company_name);

CREATE TABLE portfolio.experiences (
    experience_id    BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    profile_id       BIGINT NOT NULL REFERENCES portfolio.profile(profile_id) ON DELETE CASCADE,
    company_id       BIGINT REFERENCES portfolio.companies(company_id) ON DELETE SET NULL,
    job_title        VARCHAR(200) NOT NULL,
    employment_type  VARCHAR(100),
    start_date       DATE,
    end_date         DATE,
    is_current       BOOLEAN NOT NULL DEFAULT FALSE,
    description      TEXT,
    display_order    INTEGER NOT NULL DEFAULT 0,
    is_active        BOOLEAN NOT NULL DEFAULT TRUE,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by       BIGINT REFERENCES auth.users(user_id) ON DELETE SET NULL,
    updated_by       BIGINT REFERENCES auth.users(user_id) ON DELETE SET NULL,
    CONSTRAINT chk_experience_dates CHECK (
        (is_current = TRUE AND end_date IS NULL)
        OR (is_current = FALSE AND (end_date IS NULL OR start_date IS NULL OR end_date >= start_date))
    )
);
CREATE INDEX idx_experiences_profile_active_order ON portfolio.experiences(profile_id, is_active, display_order);
CREATE UNIQUE INDEX uq_one_current_experience_per_profile
    ON portfolio.experiences(profile_id) WHERE is_current = TRUE AND is_active = TRUE;

-- 9. LANGUAGES AND SOCIAL LINKS ---------------------------------------------
CREATE TABLE portfolio.languages (
    language_id        BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    profile_id         BIGINT NOT NULL REFERENCES portfolio.profile(profile_id) ON DELETE CASCADE,
    language_name      VARCHAR(100) NOT NULL,
    proficiency_level  SMALLINT NOT NULL CHECK (proficiency_level BETWEEN 1 AND 5),
    display_order      INTEGER NOT NULL DEFAULT 0,
    is_active          BOOLEAN NOT NULL DEFAULT TRUE,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by         BIGINT REFERENCES auth.users(user_id) ON DELETE SET NULL,
    updated_by         BIGINT REFERENCES auth.users(user_id) ON DELETE SET NULL
);
CREATE INDEX idx_languages_profile_active_order ON portfolio.languages(profile_id, is_active, display_order);

CREATE TABLE portfolio.social_links (
    social_link_id  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    profile_id      BIGINT NOT NULL REFERENCES portfolio.profile(profile_id) ON DELETE CASCADE,
    platform_name   VARCHAR(100) NOT NULL,
    link_url        TEXT NOT NULL,
    icon_name       VARCHAR(100),
    display_order   INTEGER NOT NULL DEFAULT 0,
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by      BIGINT REFERENCES auth.users(user_id) ON DELETE SET NULL,
    updated_by      BIGINT REFERENCES auth.users(user_id) ON DELETE SET NULL
);
CREATE INDEX idx_social_links_profile_active_order ON portfolio.social_links(profile_id, is_active, display_order);

-- 10. BLOGS -----------------------------------------------------------------
CREATE TABLE portfolio.blogs (
    blog_id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    profile_id       BIGINT NOT NULL REFERENCES portfolio.profile(profile_id) ON DELETE CASCADE,
    title            VARCHAR(255) NOT NULL,
    slug             VARCHAR(255) NOT NULL UNIQUE,
    summary          TEXT,
    content          TEXT NOT NULL,
    cover_media_id   BIGINT REFERENCES portfolio.media_assets(media_id) ON DELETE SET NULL,
    publication_status VARCHAR(20) NOT NULL DEFAULT 'DRAFT'
                       CHECK (publication_status IN ('DRAFT', 'PUBLISHED', 'ARCHIVED')),
    published_at     TIMESTAMPTZ,
    is_active        BOOLEAN NOT NULL DEFAULT TRUE,
    display_order    INTEGER NOT NULL DEFAULT 0,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by       BIGINT REFERENCES auth.users(user_id) ON DELETE SET NULL,
    updated_by       BIGINT REFERENCES auth.users(user_id) ON DELETE SET NULL
);
CREATE UNIQUE INDEX uq_blogs_slug_lower ON portfolio.blogs(LOWER(slug));
CREATE INDEX idx_blogs_publication ON portfolio.blogs(publication_status, is_active, published_at);

CREATE TABLE portfolio.blog_categories (
    blog_category_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    category_name    VARCHAR(100) NOT NULL UNIQUE,
    description      TEXT,
    is_active        BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE portfolio.blog_tags (
    blog_tag_id  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tag_name     VARCHAR(100) NOT NULL UNIQUE
);

CREATE TABLE portfolio.blog_tag_mapping (
    blog_id      BIGINT NOT NULL REFERENCES portfolio.blogs(blog_id) ON DELETE CASCADE,
    blog_tag_id  BIGINT NOT NULL REFERENCES portfolio.blog_tags(blog_tag_id) ON DELETE CASCADE,
    PRIMARY KEY (blog_id, blog_tag_id)
);

-- A blog may have multiple categories; use this mapping table.
CREATE TABLE portfolio.blog_category_mapping (
    blog_id          BIGINT NOT NULL REFERENCES portfolio.blogs(blog_id) ON DELETE CASCADE,
    blog_category_id BIGINT NOT NULL REFERENCES portfolio.blog_categories(blog_category_id) ON DELETE RESTRICT,
    PRIMARY KEY (blog_id, blog_category_id)
);

-- 11. CONTACT INFORMATION AND INBOUND MESSAGES -----------------------------
CREATE TABLE portfolio.contact_details (
    contact_id      BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    profile_id      BIGINT NOT NULL REFERENCES portfolio.profile(profile_id) ON DELETE CASCADE,
    contact_type    VARCHAR(50) NOT NULL,
    contact_value   VARCHAR(500) NOT NULL,
    display_order   INTEGER NOT NULL DEFAULT 0,
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by      BIGINT REFERENCES auth.users(user_id) ON DELETE SET NULL,
    updated_by      BIGINT REFERENCES auth.users(user_id) ON DELETE SET NULL
);
CREATE INDEX idx_contact_details_profile_active_order ON portfolio.contact_details(profile_id, is_active, display_order);

CREATE TABLE portfolio.contact_messages (
    message_id      BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    sender_name     VARCHAR(150) NOT NULL,
    sender_email    VARCHAR(255) NOT NULL,
    subject         VARCHAR(255),
    message         TEXT NOT NULL,
    message_status  VARCHAR(30) NOT NULL DEFAULT 'NEW'
                    CHECK (message_status IN ('NEW', 'READ', 'REPLIED', 'ARCHIVED', 'SPAM')),
    received_at     TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    handled_by      BIGINT REFERENCES auth.users(user_id) ON DELETE SET NULL,
    handled_at      TIMESTAMPTZ,
    admin_notes     TEXT
);
CREATE INDEX idx_contact_messages_status_date ON portfolio.contact_messages(message_status, received_at DESC);

-- 12. WEBSITE SETTINGS ------------------------------------------------------
CREATE TABLE portfolio.website_settings (
    setting_id     BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    setting_key    VARCHAR(150) NOT NULL UNIQUE,
    setting_value TEXT,
    description    VARCHAR(255),
    is_public      BOOLEAN NOT NULL DEFAULT TRUE,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_by     BIGINT REFERENCES auth.users(user_id) ON DELETE SET NULL
);

-- 13. AUDIT LOG -------------------------------------------------------------
-- record_id is intentionally not an FK: it can refer to records in many tables.
CREATE TABLE audit.activity_logs (
    log_id       BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id      BIGINT REFERENCES auth.users(user_id) ON DELETE SET NULL,
    action       VARCHAR(50) NOT NULL,
    schema_name  VARCHAR(100),
    table_name   VARCHAR(100),
    record_id    BIGINT,
    old_values   JSONB,
    new_values   JSONB,
    ip_address   INET,
    user_agent   TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_activity_logs_user_date ON audit.activity_logs(user_id, created_at DESC);
CREATE INDEX idx_activity_logs_table_record ON audit.activity_logs(schema_name, table_name, record_id);
CREATE INDEX idx_activity_logs_created_at ON audit.activity_logs(created_at DESC);

-- 14. updated_at TRIGGERS ----------------------------------------------------
DO $$
DECLARE
    tbl TEXT;
    auth_tables TEXT[] := ARRAY['users', 'user_roles'];
    portfolio_tables TEXT[] := ARRAY[
        'media_assets', 'profile', 'about_content', 'projects', 'skills',
        'education', 'companies', 'experiences', 'languages', 'social_links',
        'blogs', 'contact_details', 'website_settings','project_impact_metrics'
    ];
BEGIN
    FOREACH tbl IN ARRAY auth_tables LOOP
        EXECUTE format('CREATE TRIGGER trg_%I_updated_at BEFORE UPDATE ON auth.%I FOR EACH ROW EXECUTE FUNCTION public.set_updated_at()', tbl, tbl);
    END LOOP;
    FOREACH tbl IN ARRAY portfolio_tables LOOP
        EXECUTE format('CREATE TRIGGER trg_%I_updated_at BEFORE UPDATE ON portfolio.%I FOR EACH ROW EXECUTE FUNCTION public.set_updated_at()', tbl, tbl);
    END LOOP;
END $$;

-- 15. INITIAL ROLE AND PERMISSION MASTER DATA -------------------------------
INSERT INTO auth.roles (role_name, description) VALUES
    ('SUPER_ADMIN', 'Full application and administrator management access'),
    ('ADMIN', 'Manage portfolio content and approved administrative functions'),
    ('EDITOR', 'Create and edit permitted portfolio content'),
    ('USER', 'Normal registered user without administrative permissions')
ON CONFLICT (role_name) DO NOTHING;

INSERT INTO auth.permissions (permission_key, description) VALUES
    ('USER_VIEW', 'View user accounts'),
    ('USER_APPROVE', 'Approve or reject administrator role requests'),
    ('USER_MANAGE', 'Manage user accounts'),
    ('PROFILE_MANAGE', 'Manage portfolio profile'),
    ('ABOUT_MANAGE', 'Manage About content'),
    ('PROJECT_MANAGE', 'Manage projects and project media'),
    ('SKILL_MANAGE', 'Manage skills'),
    ('EDUCATION_MANAGE', 'Manage education records'),
    ('EXPERIENCE_MANAGE', 'Manage experience records'),
    ('BLOG_MANAGE', 'Manage blog posts and categories'),
    ('CONTACT_MANAGE', 'Manage contact details and messages'),
    ('MEDIA_MANAGE', 'Manage uploaded media'),
    ('AUDIT_VIEW', 'View audit history'),
    ('SETTINGS_MANAGE', 'Manage website settings')
ON CONFLICT (permission_key) DO NOTHING;

-- SUPER_ADMIN receives all permissions. ADMIN receives content permissions;
-- USER and EDITOR assignments can be customized later.
INSERT INTO auth.role_permissions (role_id, permission_id)
SELECT r.role_id, p.permission_id
FROM auth.roles r CROSS JOIN auth.permissions p
WHERE r.role_name = 'SUPER_ADMIN'
ON CONFLICT DO NOTHING;

INSERT INTO auth.role_permissions (role_id, permission_id)
SELECT r.role_id, p.permission_id
FROM auth.roles r
CROSS JOIN auth.permissions p
WHERE r.role_name = 'ADMIN'
  AND p.permission_key IN (
      'PROFILE_MANAGE', 'ABOUT_MANAGE', 'PROJECT_MANAGE', 'SKILL_MANAGE',
      'EDUCATION_MANAGE', 'EXPERIENCE_MANAGE', 'BLOG_MANAGE',
      'CONTACT_MANAGE', 'MEDIA_MANAGE'
  )
ON CONFLICT DO NOTHING;

-- 16. OPTIONAL STARTER MASTER DATA ------------------------------------------
INSERT INTO portfolio.skill_categories (category_name, display_order) VALUES
    ('Programming', 1),
    ('Database', 2),
    ('Data Visualization', 3),
    ('Cloud', 4),
    ('Data Engineering', 5),
    ('Tools', 6)
ON CONFLICT (category_name) DO NOTHING;

INSERT INTO portfolio.website_settings (setting_key, setting_value, description, is_public) VALUES
    ('site_name', 'My Portfolio', 'Public website name', TRUE),
    ('site_tagline', 'Personal portfolio website', 'Short website tagline', TRUE),
    ('default_theme', 'dark', 'Default frontend theme', TRUE)
ON CONFLICT (setting_key) DO NOTHING;

COMMIT;

-- 17. QUICK VALIDATION ------------------------------------------------------
-- Run these after executing the script to inspect created tables and roles.
-- SELECT table_schema, table_name
-- FROM information_schema.tables
-- WHERE table_schema IN ('auth', 'portfolio', 'audit')
--   AND table_type = 'BASE TABLE'
-- ORDER BY table_schema, table_name;
-- SELECT role_id, role_name FROM auth.roles ORDER BY role_id;
-- SELECT permission_key FROM auth.permissions ORDER BY permission_key;

-- IMPORTANT FIRST-ADMIN SETUP:
-- 1. Register your own account through the application (or insert it securely).
-- 2. Verify the email address.
-- 3. Assign SUPER_ADMIN to that user in auth.user_roles with APPROVED status.
-- 4. Never store a plain-text password in this database.
-- Example after a user exists and has been email-verified:
-- INSERT INTO auth.user_roles (user_id, role_id, approval_status, approved_at)
-- SELECT u.user_id, r.role_id, 'APPROVED', CURRENT_TIMESTAMP
-- FROM auth.users u CROSS JOIN auth.roles r
-- WHERE LOWER(u.email) = LOWER('your-email@example.com')
--   AND r.role_name = 'SUPER_ADMIN'
-- ON CONFLICT (user_id, role_id) DO UPDATE
-- SET approval_status = 'APPROVED', approved_at = CURRENT_TIMESTAMP;
