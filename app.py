from flask import Flask, render_template, request, redirect, session, jsonify
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime
from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__)

# ---------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------

app.secret_key = os.getenv("FLASK_SECRET_KEY")

DB_CONFIG = {
    "host": os.getenv("DB_HOST"),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASSWORD"),
    "database": os.getenv("DB_NAME")
}


# ---------------------------------------------------------
# DATABASE CONNECTION
# ---------------------------------------------------------

def get_db_connection():
    return mysql.connector.connect(**DB_CONFIG)


# ---------------------------------------------------------
# LOGIN REQUIRED
# ---------------------------------------------------------

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):

        if "user_id" not in session:
            return redirect("/login")

        return f(*args, **kwargs)

    return decorated_function


# ---------------------------------------------------------
# ADMIN REQUIRED
# ---------------------------------------------------------

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):

        if "user_id" not in session:
            return redirect("/login")

        if session.get("role") != "admin":
            return redirect("/")

        return f(*args, **kwargs)

    return decorated_function


# ---------------------------------------------------------
# DATABASE HELPERS
# ---------------------------------------------------------

def record_activity(cursor, user_id, action, ip_address):

    cursor.execute(
        """
        INSERT INTO activity_logs
        (user_id, action, ip_address)
        VALUES (%s, %s, %s)
        """,
        (user_id, action, ip_address)
    )


def record_login_attempt(cursor, user_id, ip_address, success):

    cursor.execute(
        """
        INSERT INTO login_attempts
        (user_id, ip_address, success)
        VALUES (%s, %s, %s)
        """,
        (user_id, ip_address, success)
    )


def update_suspicious_ip(cursor, ip_address):

    cursor.execute(
        """
        SELECT failed_attempts
        FROM suspicious_ips
        WHERE ip_address = %s
        """,
        (ip_address,)
    )

    result = cursor.fetchone()

    if result:

        cursor.execute(
            """
            UPDATE suspicious_ips
            SET failed_attempts = failed_attempts + 1
            WHERE ip_address = %s
            """,
            (ip_address,)
        )

    else:

        cursor.execute(
            """
            INSERT INTO suspicious_ips
            (ip_address, failed_attempts)
            VALUES (%s, 1)
            """,
            (ip_address,)
        )


def get_suspicious_ip_count(cursor, ip_address):

    cursor.execute(
        """
        SELECT failed_attempts
        FROM suspicious_ips
        WHERE ip_address = %s
        """,
        (ip_address,)
    )

    result = cursor.fetchone()

    if result:
        return result["failed_attempts"]

    return 0


def create_security_alert(cursor, user_id, alert_type, description):

    cursor.execute(
        """
        INSERT INTO security_alerts
        (user_id, alert_type, description)
        VALUES (%s, %s, %s)
        """,
        (user_id, alert_type, description)
    )


# ---------------------------------------------------------
# LOGIN
# ---------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "GET":

        if "user_id" in session:
            return redirect("/")

        message = None

        if request.args.get("registered") == "1":
            message = "Account created successfully. You can now sign in."

        return render_template(
            "login.html",
            message=message
        )

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not username or not password:

        return render_template(
            "login.html",
            message="Please enter your username and password."
        )

    ip_address = request.remote_addr or "Unknown"

    connection = None
    cursor = None

    try:

        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        # -------------------------------------------------
        # FIND USER
        # -------------------------------------------------

        cursor.execute(
            """
            SELECT *
            FROM users
            WHERE username = %s
            """,
            (username,)
        )

        user = cursor.fetchone()

        # -------------------------------------------------
        # UNKNOWN USER
        # -------------------------------------------------

        if not user:

            record_login_attempt(
                cursor,
                None,
                ip_address,
                False
            )

            update_suspicious_ip(
                cursor,
                ip_address
            )

            ip_count = get_suspicious_ip_count(
                cursor,
                ip_address
            )

            if ip_count == 3:

                create_security_alert(
                    cursor,
                    None,
                    "Suspicious IP",
                    f"Multiple failed login attempts detected from {ip_address}"
                )

            connection.commit()

            return render_template(
                "login.html",
                message="Invalid username or password."
            )

        user_id = user["user_id"]

        # -------------------------------------------------
        # BLOCKED ACCOUNT
        # -------------------------------------------------

        # Admin accounts can still log in.
        # Normal users cannot log in when blocked.

        if (
            user["account_status"] == "Blocked"
            and user["role"] != "admin"
        ):

            record_login_attempt(
                cursor,
                user_id,
                ip_address,
                False
            )

            record_activity(
                cursor,
                user_id,
                "Blocked login attempt",
                ip_address
            )

            connection.commit()

            return render_template(
                "login.html",
                message="This account has been blocked."
            )

        # -------------------------------------------------
        # PASSWORD CHECK
        # -------------------------------------------------

        stored_password = user["password_hash"]

        password_valid = False

        # Modern hashed password
        if (
            stored_password.startswith("pbkdf2:")
            or stored_password.startswith("scrypt:")
        ):

            try:

                password_valid = check_password_hash(
                    stored_password,
                    password
                )

            except Exception:

                password_valid = False

        # Legacy plaintext password
        else:

            password_valid = stored_password == password

            # Upgrade plaintext password
            if password_valid:

                new_hash = generate_password_hash(password)

                cursor.execute(
                    """
                    UPDATE users
                    SET password_hash = %s
                    WHERE user_id = %s
                    """,
                    (new_hash, user_id)
                )

        # -------------------------------------------------
        # SUCCESSFUL LOGIN
        # -------------------------------------------------

        if password_valid:

            record_login_attempt(
                cursor,
                user_id,
                ip_address,
                True
            )

            record_activity(
                cursor,
                user_id,
                "Successful login",
                ip_address
            )

            cursor.execute(
                """
                UPDATE users
                SET
                    failed_attempts = 0,
                    last_failed_ip = NULL,
                    account_status = 'Active'
                WHERE user_id = %s
                """,
                (user_id,)
            )

            connection.commit()

            # Create fresh session
            session.clear()

            session["user_id"] = user_id
            session["username"] = user["username"]
            session["role"] = user["role"]

            return redirect("/")

        # -------------------------------------------------
        # FAILED LOGIN
        # -------------------------------------------------

        cursor.execute(
            """
            UPDATE users
            SET
                failed_attempts = failed_attempts + 1,
                last_failed_ip = %s
            WHERE user_id = %s
            """,
            (ip_address, user_id)
        )

        record_login_attempt(
            cursor,
            user_id,
            ip_address,
            False
        )

        record_activity(
            cursor,
            user_id,
            "Failed login attempt",
            ip_address
        )

        update_suspicious_ip(
            cursor,
            ip_address
        )

        # Get updated failed count
        cursor.execute(
            """
            SELECT failed_attempts
            FROM users
            WHERE user_id = %s
            """,
            (user_id,)
        )

        updated_user = cursor.fetchone()

        failed_count = updated_user["failed_attempts"]

        # -------------------------------------------------
        # ACCOUNT BLOCK AFTER 3 FAILURES
        # -------------------------------------------------

        if (
            failed_count >= 3
            and user["role"] != "admin"
        ):

            cursor.execute(
                """
                UPDATE users
                SET account_status = 'Blocked'
                WHERE user_id = %s
                """,
                (user_id,)
            )

            create_security_alert(
                cursor,
                user_id,
                "Brute Force",
                f"Account {username} automatically blocked after {failed_count} failed login attempts from {ip_address}"
            )

            record_activity(
                cursor,
                user_id,
                "Account automatically blocked",
                ip_address
            )

            connection.commit()

            return render_template(
                "login.html",
                message="Too many failed attempts. Your account has been blocked."
            )

        # -------------------------------------------------
        # SUSPICIOUS IP ALERT
        # -------------------------------------------------

        ip_count = get_suspicious_ip_count(
            cursor,
            ip_address
        )

        if ip_count == 3:

            create_security_alert(
                cursor,
                user_id,
                "Suspicious IP",
                f"Multiple failed login attempts detected from {ip_address}"
            )

        connection.commit()

        remaining = max(0, 3 - failed_count)

        return render_template(
            "login.html",
            message=f"Invalid username or password. Attempts remaining: {remaining}"
        )

    except mysql.connector.Error as error:

        if connection:
            connection.rollback()

        print("Database error:", error)

        return render_template(
            "login.html",
            message="A database error occurred. Please try again."
        )

    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()


# ---------------------------------------------------------
# SIGN UP
# ---------------------------------------------------------

@app.route("/signup", methods=["GET", "POST"])
def signup():

    if "user_id" in session:
        return redirect("/")

    if request.method == "GET":

        return render_template(
            "signup.html",
            message=None
        )

    username = request.form.get("username", "").strip()
    email = request.form.get("email", "").strip()
    password = request.form.get("password", "")
    confirm_password = request.form.get("confirm_password", "")

    # Validation

    if not username or not email or not password:

        return render_template(
            "signup.html",
            message="Please complete all fields."
        )

    if password != confirm_password:

        return render_template(
            "signup.html",
            message="Passwords do not match."
        )

    if len(password) < 6:

        return render_template(
            "signup.html",
            message="Password must contain at least 6 characters."
        )

    connection = None
    cursor = None

    try:

        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        # Check username

        cursor.execute(
            """
            SELECT user_id
            FROM users
            WHERE username = %s
            """,
            (username,)
        )

        if cursor.fetchone():

            return render_template(
                "signup.html",
                message="Username already exists."
            )

        # Check email

        cursor.execute(
            """
            SELECT user_id
            FROM users
            WHERE email = %s
            """,
            (email,)
        )

        if cursor.fetchone():

            return render_template(
                "signup.html",
                message="Email is already registered."
            )

        # Hash password

        password_hash = generate_password_hash(password)

        # Create normal user account
        # role automatically becomes "user"
        # because of the database DEFAULT.

        cursor.execute(
            """
            INSERT INTO users
            (
                username,
                password_hash,
                email,
                account_status,
                failed_attempts,
                role
            )
            VALUES (%s, %s, %s, 'Active', 0, 'user')
            """,
            (
                username,
                password_hash,
                email
            )
        )

        user_id = cursor.lastrowid

        # Activity log

        record_activity(
            cursor,
            user_id,
            "Account created",
            request.remote_addr or "Unknown"
        )

        connection.commit()

        return redirect("/login?registered=1")

    except mysql.connector.Error as error:

        if connection:
            connection.rollback()

        print("Signup database error:", error)

        return render_template(
            "signup.html",
            message="Could not create the account. Please try again."
        )

    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()


# ---------------------------------------------------------
# MAIN PAGE
# ---------------------------------------------------------

@app.route("/")
@login_required
def dashboard():

    # Admin gets the full cybersecurity dashboard.
    if session.get("role") == "admin":

        return render_template(
            "dashboard.html",
            username=session.get("username")
        )

    # Normal users get their own portal.
    return render_template(
        "user_dashboard.html",
        username=session.get("username")
    )


# ---------------------------------------------------------
# ADMIN DASHBOARD API
# ---------------------------------------------------------

@app.route("/api/dashboard")
@admin_required
def dashboard_api():

    connection = None
    cursor = None

    try:

        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        # -------------------------------------------------
        # TOTAL USERS
        # -------------------------------------------------

        cursor.execute(
            """
            SELECT COUNT(*) AS total
            FROM users
            """
        )

        total_users = cursor.fetchone()["total"]

        # -------------------------------------------------
        # FAILED LOGINS
        # -------------------------------------------------

        cursor.execute(
            """
            SELECT COUNT(*) AS total
            FROM login_attempts
            WHERE success = 0
            """
        )

        failed_logins = cursor.fetchone()["total"]

        # -------------------------------------------------
        # SECURITY ALERTS
        # -------------------------------------------------

        cursor.execute(
            """
            SELECT COUNT(*) AS total
            FROM security_alerts
            """
        )

        security_alerts = cursor.fetchone()["total"]

        # -------------------------------------------------
        # BLOCKED ACCOUNTS
        # -------------------------------------------------

        cursor.execute(
            """
            SELECT COUNT(*) AS total
            FROM users
            WHERE account_status = 'Blocked'
            """
        )

        blocked_accounts = cursor.fetchone()["total"]

        # -------------------------------------------------
        # SUCCESSFUL LOGINS
        # -------------------------------------------------

        cursor.execute(
            """
            SELECT COUNT(*) AS total
            FROM login_attempts
            WHERE success = 1
            """
        )

        successful_logins = cursor.fetchone()["total"]

        # -------------------------------------------------
        # SUSPICIOUS IPS
        # -------------------------------------------------

        cursor.execute(
            """
            SELECT COUNT(*) AS total
            FROM suspicious_ips
            WHERE failed_attempts >= 3
            """
        )

        suspicious_ips = cursor.fetchone()["total"]

        # -------------------------------------------------
        # USERS
        # -------------------------------------------------

        cursor.execute(
            """
            SELECT
                user_id,
                username,
                email,
                role,
                account_status,
                failed_attempts,
                last_failed_ip,
                created_at
            FROM users
            ORDER BY user_id DESC
            """
        )

        users = cursor.fetchall()

        # -------------------------------------------------
        # SECURITY ALERTS
        # -------------------------------------------------

        cursor.execute(
            """
            SELECT
                sa.alert_id,
                sa.alert_type,
                sa.description,
                sa.alert_time,
                u.username
            FROM security_alerts sa
            LEFT JOIN users u
                ON sa.user_id = u.user_id
            ORDER BY sa.alert_time DESC
            LIMIT 12
            """
        )

        alerts = cursor.fetchall()

        # -------------------------------------------------
        # SUSPICIOUS IPS
        # -------------------------------------------------

        cursor.execute(
            """
            SELECT
                ip_address,
                failed_attempts
            FROM suspicious_ips
            ORDER BY failed_attempts DESC
            LIMIT 10
            """
        )

        suspicious_ip_list = cursor.fetchall()

        # -------------------------------------------------
        # RECENT LOGIN ATTEMPTS
        # -------------------------------------------------

        cursor.execute(
            """
            SELECT
                la.attempt_id,
                la.attempt_time,
                la.ip_address,
                la.success,
                u.username
            FROM login_attempts la
            LEFT JOIN users u
                ON la.user_id = u.user_id
            ORDER BY la.attempt_time DESC
            LIMIT 12
            """
        )

        login_attempts = cursor.fetchall()

        # -------------------------------------------------
        # ACTIVITY
        # -------------------------------------------------

        cursor.execute(
            """
            SELECT
                al.log_id,
                al.action,
                al.ip_address,
                al.log_time,
                u.username
            FROM activity_logs al
            LEFT JOIN users u
                ON al.user_id = u.user_id
            ORDER BY al.log_time DESC
            LIMIT 12
            """
        )

        activities = cursor.fetchall()

        # -------------------------------------------------
        # CONVERT DATETIME OBJECTS
        # -------------------------------------------------

        def serialize(rows):

            for row in rows:

                for key, value in row.items():

                    if isinstance(value, datetime):

                        row[key] = value.strftime(
                            "%Y-%m-%d %H:%M:%S"
                        )

            return rows

        users = serialize(users)
        alerts = serialize(alerts)
        suspicious_ip_list = serialize(suspicious_ip_list)
        login_attempts = serialize(login_attempts)
        activities = serialize(activities)

        return jsonify({

            "stats": {
                "total_users": total_users,
                "failed_logins": failed_logins,
                "security_alerts": security_alerts,
                "blocked_accounts": blocked_accounts,
                "successful_logins": successful_logins,
                "suspicious_ips": suspicious_ips
            },

            "users": users,

            "alerts": alerts,

            "suspicious_ips": suspicious_ip_list,

            "login_attempts": login_attempts,

            "activities": activities,

            "system": {
                "database": "ONLINE",
                "authentication": "ACTIVE",
                "monitoring": "ACTIVE",
                "api": "ONLINE"
            }

        })

    except mysql.connector.Error as error:

        print("Dashboard API error:", error)

        return jsonify({
            "error": "Database connection error"
        }), 500

    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()


# ---------------------------------------------------------
# NORMAL USER DASHBOARD API
# ---------------------------------------------------------

@app.route("/api/user-dashboard")
@login_required
def user_dashboard_api():

    if session.get("role") == "admin":
        return jsonify({
            "error": "Admin users must use the admin dashboard."
        }), 403

    connection = None
    cursor = None

    try:

        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        user_id = session.get("user_id")

        # -------------------------------------------------
        # USER INFORMATION
        # -------------------------------------------------

        cursor.execute(
            """
            SELECT
                user_id,
                username,
                email,
                role,
                account_status,
                failed_attempts,
                last_failed_ip,
                created_at
            FROM users
            WHERE user_id = %s
            """,
            (user_id,)
        )

        user = cursor.fetchone()

        if not user:

            session.clear()

            return jsonify({
                "error": "User account not found."
            }), 404

        # -------------------------------------------------
        # LOGIN HISTORY
        # -------------------------------------------------

        cursor.execute(
            """
            SELECT
                attempt_time,
                ip_address,
                success
            FROM login_attempts
            WHERE user_id = %s
            ORDER BY attempt_time DESC
            LIMIT 10
            """,
            (user_id,)
        )

        login_history = cursor.fetchall()

        # -------------------------------------------------
        # USER ACTIVITY
        # -------------------------------------------------

        cursor.execute(
            """
            SELECT
                action,
                ip_address,
                log_time
            FROM activity_logs
            WHERE user_id = %s
            ORDER BY log_time DESC
            LIMIT 10
            """,
            (user_id,)
        )

        activities = cursor.fetchall()

        # -------------------------------------------------
        # USER ALERTS
        # -------------------------------------------------

        cursor.execute(
            """
            SELECT
                alert_type,
                description,
                alert_time
            FROM security_alerts
            WHERE user_id = %s
            ORDER BY alert_time DESC
            LIMIT 10
            """,
            (user_id,)
        )

        alerts = cursor.fetchall()

        # -------------------------------------------------
        # SERIALIZE DATES
        # -------------------------------------------------

        def serialize(rows):

            for row in rows:

                for key, value in row.items():

                    if isinstance(value, datetime):

                        row[key] = value.strftime(
                            "%Y-%m-%d %H:%M:%S"
                        )

            return rows

        user = serialize([user])[0]
        login_history = serialize(login_history)
        activities = serialize(activities)
        alerts = serialize(alerts)

        return jsonify({

            "user": user,

            "login_history": login_history,

            "activities": activities,

            "alerts": alerts

        })

    except mysql.connector.Error as error:

        print("User dashboard API error:", error)

        return jsonify({
            "error": "Database connection error"
        }), 500

    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()


# ---------------------------------------------------------
# LOGOUT
# ---------------------------------------------------------

@app.route("/logout")
@login_required
def logout():

    user_id = session.get("user_id")

    connection = None
    cursor = None

    try:

        connection = get_db_connection()
        cursor = connection.cursor()

        record_activity(
            cursor,
            user_id,
            "User logged out",
            request.remote_addr or "Unknown"
        )

        connection.commit()

    except mysql.connector.Error as error:

        print("Logout database error:", error)

    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()

    session.clear()

    return redirect("/login")


# ---------------------------------------------------------
# RUN APPLICATION
# ---------------------------------------------------------

if __name__ == "__main__":

    app.run(
        debug=True,
        host="127.0.0.1",
        port=5000
    )