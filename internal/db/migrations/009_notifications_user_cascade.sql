-- So Purge (DELETE FROM users) removes bot notification history for the user
-- in one go; otherwise the implicit NO ACTION on notifications blocks deletes.
ALTER TABLE notifications
  DROP CONSTRAINT IF EXISTS notifications_user_uuid_fkey;
ALTER TABLE notifications
  ADD CONSTRAINT notifications_user_uuid_fkey
  FOREIGN KEY (user_uuid) REFERENCES users(uuid) ON DELETE CASCADE;
