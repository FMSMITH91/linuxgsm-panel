# Permissions and the Databases manager

Back to the [README](README.md). What each feature does: [features.md](features.md).

## Permissions

Groups grant any mix of these, scoped to specific servers/hosts. Super Admin is **not** one of
them — it is the `is_superadmin` flag on the account, set on the Users page, and it bypasses every
check.

| Permission | Grants |
|------------|--------|
| `view_servers` / `view_console` / `view_logs` | See status / console / audit logs |
| `send_command` | Send raw console commands |
| `use_terminal` | Open a shell on a host, as the account the panel uses there, which on most installs can become root: grant it only to people you would give that account |
| `moderate_server` | Umbrella for `kick_player` + `ban_player` + `say_server` (also grantable individually) |
| `start_server` / `stop_server` / `restart_server` / `update_server` | Power & update controls |
| `install_server` / `uninstall_server` / `manage_servers` | Add, remove, and define game servers; `manage_servers` also covers a server's schedule, alerts and mods. A scheduled task runs any command as the game account, so adding, changing, deleting or running one on the Scheduled Tasks card also needs `edit_files`, and a failed task's output shows only with `view_files` too; with those, `manage_servers` amounts to running commands as that account. Without `edit_files` the card lists the tasks and says why it cannot change them |
| `view_files` / `edit_files` | Browse, read and download a server's files and configs, including the passwords in them / upload, edit, rename, create and delete them and save its config forms (give `view_files` with it). LinuxGSM runs a game's config files as a script, so `edit_files` amounts to running commands as that game account: give it only to someone you would trust with that account's login. When the panel's [SFTP service](sftp.md) is on, `edit_files` also shows the server's folder over SFTP, where the user can do the same with any SFTP client (reading there needs `view_files` too) |
| `download_backup` / `delete_backup` | Download / delete a game server's backup archives (a deleted backup is gone for good). Taking a backup, its schedule and the panel's own backups stay with superadmins |
| `restore_backup` | Restore a game server from one of its backups: the server is stopped, a backup of its current state is taken first, then its files are replaced with the archive's (the account's SSH keys and shell start-up files are kept as they are, never taken from the archive). The most destructive backup permission. Uploading a backup to restore also needs `edit_files` (an uploaded archive can hold any file, including the scripts the server runs). An archive's config files run as the game account at the server's next start, so this too amounts to running commands as that account |
| `manage_databases` | A server's MariaDB/MySQL databases: add, delete, restore and reset them, and see their passwords. Given to no group by default. Setting up a host's database server also needs `manage_remotes`; the admin login of an existing server is for superadmins |
| `manage_addons` | A server's add-ons: install, update, start, stop and remove them, change their settings, read their logs, and look B3's players and penalties up (their IP addresses and GUIDs only with `manage_databases` as well; unbanning one through B3 with `ban_player` as well, kicking or warning one with `kick_player`). Installing the first one on a host installs Podman through the helper. Given to no group by default |
| `view_addon_pages` | Open a server's add-on web pages (IW4MAdmin's webfront, BlueMap's map) through the panel, in a new tab, without managing the add-ons: its Add-ons tab then lists only the installed add-ons that have a page. `manage_addons` opens them too. The page runs sandboxed, apart from the panel's own pages ([add-ons](addons.md#web-pages)). Given to no group by default |
| `edit_database_data` | Change the data inside a server's databases on the Databases page: edit rows and run SQL statements, always as that database's own account. Given to no group by default; give it with `manage_databases`, which browsing (and the manager itself) needs |
| `manage_remotes` / `manage_users` / `manage_groups` | Manage hosts / users / groups. For a host admin who is not a superadmin: re-trusting a host's SSH key is superadmin-only (the next connection trusts whatever machine answers at that address and signs in with the host's saved credential) |

### The panel owner

One account is the panel's **owner**: the one the setup wizard creates (on an upgraded install, the
active superadmin with the lowest id). It is marked **Owner** on the Users page, and no other
administrator can deactivate, demote, rename or delete it, or reset its password or 2FA, so one
superadmin cannot take the panel from another. The owner can still change their own display name,
password, 2FA and sessions on the Account page. A terminal on the panel's own host, and restoring or
downloading a panel backup, are the owner's only: each reaches the panel's database, where every
account lives, or the keys that sign every sign-in. The root cron page (root's crontab on any host) is the owner's only too.

To hand the panel over, the owner uses **Account → Panel owner → Transfer ownership**: it goes to
another active superadmin who has 2FA turned on, and is confirmed with the owner's password and a
current authenticator code (so the owner needs 2FA on too). Both accounts see the change at their
next sign-in. If the owner can no longer sign in, ownership is moved from the panel host's shell
(see [Recovery](security-features.md#recovery)).

## The Databases manager

The **Databases** page (sidebar) lists every database of the servers you can see. With `manage_databases`
it is also where you manage them: **Add a database** (choose the game server, give a name), and a
**Manage** button per database that opens it:

- **Connection**: host, port, database, user and password, each with a copy button (revealing or copying
  the password is audited).
- **Tables**: each table's approximate row count, size and columns, and its rows 50 at a time. Long values
  are cut (**Show all** reads the whole one), binary values show their length, and a NUL character inside
  text shows as ␀ (such a value is changed through the SQL box, not the row editor). With `edit_database_data`,
  **Add row**, **Edit** and **Delete** change one row at a time, addressed by its primary key; a view or a
  table without a primary key is read-only here.
- **SQL** (with `edit_database_data`): one statement per run, for at most 30 seconds, with at most 200 rows
  shown. SELECT, SHOW, DESCRIBE and EXPLAIN run at once in a read-only transaction; anything else shows
  the statement and asks you to confirm it first (each confirmation runs it once). MySQL runs each statement as a prepared statement, so
  a few kinds (DESCRIBE, CREATE TRIGGER/PROCEDURE) are not available there: use SHOW COLUMNS FROM.
  On MariaDB the 30 seconds stop the statement that is running; a stored procedure whose `SLEEP()` is
  cut short carries on with its next statement (that is MariaDB's behaviour), so a procedure is better
  tried on a copy first.
- **Dump and restore**: download a dump (it is written to the server's files as
  `panel-db-dumps/<name>.sql.gz` first, the file each backup writes), or upload a `.sql` / `.sql.gz` dump
  (up to 2 GiB) to replace the database's contents. The upload is checked on the host before anything is
  restored: a dump that switches to or names another database (`USE`, `CREATE DATABASE`, made with
  `--databases`) is refused, and so is one holding SQL the check cannot read safely (an `sql_mode` or
  character set that changes how quotes are read, `PREPARE`/`EXECUTE`, `LOAD DATA`, or a client
  command such as `\C`). The check reads the SQL as the database client does, so data that only
  mentions a statement is restored as it is. A plain `mysqldump` or `mariadb-dump` of the one database
  passes.
- **Password and delete**: reset the password, restore from the dump in the server's files, delete.
  These and an upload ask for your password again when you last confirmed it more than a few minutes ago,
  and delete and restore also ask you to type the database's name.

Everything runs as **that database's own account**, never the server's admin login, so the database
server itself keeps every statement inside that one database; the panel only ever touches the `gs<id>_…`
databases it made. Statements and values travel to the database client as hexadecimal and run through
the server's prepared statements, so nothing typed can run a client command.

**What is logged** (the audit log): opening a table, every row change (the table, the columns and how many
rows; never a value), every SQL statement (its kind, the database, how many rows, and the statement with
each quoted value replaced by `?`), each dump download and each upload.

