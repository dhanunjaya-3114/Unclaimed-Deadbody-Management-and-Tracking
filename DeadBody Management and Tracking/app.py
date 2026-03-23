import re
import secrets
from datetime import date
from functools import wraps

from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash


def create_app():
    app = Flask(__name__)
    app.config.from_pyfile("config.py")
    return app


app = create_app()
db = SQLAlchemy()
db.init_app(app)
migrate = Migrate(app, db)


class Role(db.Model):
    r_id = db.Column(db.Integer, primary_key=True)
    rolename = db.Column(db.String(50), unique=True, nullable=False)


class User(db.Model):
    u_id = db.Column(db.Integer, primary_key=True)
    u_email = db.Column(db.String(120), unique=True, nullable=False)
    u_password = db.Column(db.String(255), nullable=False)
    fk_r_id = db.Column(db.Integer, db.ForeignKey(Role.r_id), nullable=False)
    role = db.relationship(Role, backref="users", lazy=True)


class DeadBody(db.Model):
    body_id = db.Column(db.Integer, primary_key=True)
    tag_number = db.Column(db.String(40), unique=True, nullable=False)
    gender = db.Column(db.String(20), nullable=False)
    approx_age = db.Column(db.Integer)
    height = db.Column(db.String(20))
    body_build = db.Column(db.String(20))
    complexion = db.Column(db.String(20))
    identifying_marks = db.Column(db.String(250))
    clothing_description = db.Column(db.String(250))
    missing_teeth = db.Column(db.Integer)
    dental_notes = db.Column(db.String(250))
    date_found = db.Column(db.Date, nullable=False, default=date.today)
    found_location = db.Column(db.String(150), nullable=False)
    registered_by = db.Column(db.String(120), nullable=False)
    status = db.Column(db.String(30), nullable=False, default="Unclaimed")
    cremation_date = db.Column(db.Date)
    death_certificate = db.Column(db.String(120))


class ClaimRequest(db.Model):
    claim_id = db.Column(db.Integer, primary_key=True)
    body_id = db.Column(db.Integer, db.ForeignKey(DeadBody.body_id), nullable=False)
    claimant_name = db.Column(db.String(120), nullable=False)
    claimant_email = db.Column(db.String(120), nullable=False)
    claimant_phone = db.Column(db.String(25), nullable=False)
    claimant_relation = db.Column(db.String(80), nullable=False)
    submitted_on = db.Column(db.Date, nullable=False, default=date.today)
    status = db.Column(db.String(20), nullable=False, default="Pending")
    reviewed_by = db.Column(db.String(120))
    review_note = db.Column(db.String(250))
    body = db.relationship(DeadBody, backref="claims", lazy=True)


def get_or_create_csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


@app.context_processor
def inject_csrf_token():
    return {"csrf_token": get_or_create_csrf_token()}


@app.before_request
def csrf_protect():
    if request.method != "POST":
        return
    token_in_session = session.get("csrf_token")
    token_from_form = request.form.get("csrf_token")
    if not token_in_session or not token_from_form or token_in_session != token_from_form:
        flash("Invalid CSRF token. Refresh and try again.", "error")
        return redirect(request.referrer or url_for("home_page"))


def current_role_name():
    role_name = session.get("role_name")
    if role_name:
        return role_name
    role_id = session.get("fk_r_id")
    if not role_id:
        return None
    role = Role.query.get(role_id)
    if role:
        session["role_name"] = role.rolename
        return role.rolename
    return None


def role_id_by_name(role_name):
    role = Role.query.filter_by(rolename=role_name).first()
    return role.r_id if role else None


def role_required(*allowed_roles):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            role_name = current_role_name()
            if role_name not in allowed_roles:
                flash("You do not have permission to access this page.", "error")
                return redirect(url_for("dashboard_page"))
            return f(*args, **kwargs)

        return wrapped

    return decorator


def is_password_hashed(password_text):
    return password_text.startswith("scrypt:") or password_text.startswith("pbkdf2:")


def verify_user_password(user, candidate_password):
    stored = user.u_password or ""
    if is_password_hashed(stored):
        return check_password_hash(stored, candidate_password)

    # Backward compatibility for old plaintext rows, with automatic secure upgrade.
    if stored == candidate_password:
        user.u_password = generate_password_hash(candidate_password)
        db.session.commit()
        return True
    return False


def parse_optional_int(raw_value, field_name, min_value, max_value):
    value = (raw_value or "").strip()
    if not value:
        return None
    if not value.isdigit():
        raise ValueError(f"{field_name} must be a number.")
    parsed = int(value)
    if parsed < min_value or parsed > max_value:
        raise ValueError(f"{field_name} must be between {min_value} and {max_value}.")
    return parsed


def parse_found_date(raw_value):
    value = (raw_value or "").strip()
    if not value:
        return date.today()
    try:
        found_date = date.fromisoformat(value)
    except ValueError as exc:
        raise ValueError("Invalid date format.") from exc
    if found_date > date.today():
        raise ValueError("Found date cannot be in the future.")
    return found_date


def create_roles():
    roles = ["Admin", "Nurse", "Police", "Public"]
    existing = {r.rolename for r in Role.query.all()}
    for role_name in roles:
        if role_name not in existing:
            db.session.add(Role(rolename=role_name))
    db.session.commit()


def admin_by_default():
    check_admin = User.query.filter_by(u_email="admin@gmail.com").first()
    if not check_admin:
        admin_role_id = role_id_by_name("Admin")
        if not admin_role_id:
            return
        db.session.add(
            User(
                u_email="admin@gmail.com",
                u_password=generate_password_hash("Admin_45"),
                fk_r_id=admin_role_id,
            )
        )
        db.session.commit()


def generate_tag_number():
    today = date.today().strftime("%Y%m%d")
    latest = (
        DeadBody.query.filter(DeadBody.tag_number.like(f"DB-{today}-%"))
        .order_by(DeadBody.body_id.desc())
        .first()
    )
    if not latest:
        return f"DB-{today}-001"

    try:
        last_seq = int(latest.tag_number.split("-")[-1])
    except ValueError:
        last_seq = 0
    return f"DB-{today}-{last_seq + 1:03d}"


def ensure_seed_data():
    db.create_all()
    create_roles()
    admin_by_default()


@app.route("/")
def home_page():
    return render_template("home.html")


@app.route("/about")
def aboutpage():
    return render_template("aboutuspage.html")


@app.route("/contact")
def contactpage():
    return render_template("contact.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html", next_url=request.args.get("next", "").strip())

    form_email = request.form.get("u_email", "").strip()
    form_password = request.form.get("u_password", "").strip()
    user = User.query.filter_by(u_email=form_email).first()

    if user and verify_user_password(user, form_password):
        session["u_id"] = user.u_id
        session["u_email"] = user.u_email
        session["fk_r_id"] = user.fk_r_id
        session["role_name"] = user.role.rolename if user.role else None
        get_or_create_csrf_token()
        next_url = request.form.get("next", "").strip()
        if next_url and next_url.startswith("/"):
            return redirect(next_url)
        return redirect(url_for("dashboard_page"))

    flash("Invalid email or password.", "error")
    return redirect(url_for("login"))


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "GET":
        return render_template("signup.html")

    form_email = request.form.get("u_email", "").strip()
    form_password = request.form.get("u_password", "").strip()

    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", form_email):
        flash("Please enter a valid email address.", "error")
        return redirect(url_for("signup"))
    if len(form_password) < 8:
        flash("Password must be at least 8 characters.", "error")
        return redirect(url_for("signup"))

    if not form_email or not form_password:
        flash("Email and password are required.", "error")
        return redirect(url_for("signup"))

    existing = User.query.filter_by(u_email=form_email).first()
    if existing:
        flash("Account already exists. Please login.", "error")
        return redirect(url_for("login"))

    # New self-signups are Public role users.
    public_role_id = role_id_by_name("Public")
    if not public_role_id:
        flash("Public role is not configured.", "error")
        return redirect(url_for("signup"))

    db.session.add(
        User(
            u_email=form_email,
            u_password=generate_password_hash(form_password),
            fk_r_id=public_role_id,
        )
    )
    db.session.commit()
    flash("Signup successful. Please login.", "success")
    return redirect(url_for("login"))


@app.route("/dashboard")
def dashboard_page():
    role = current_role_name()
    mail = session.get("u_email")

    if not role:
        return redirect(url_for("login"))

    latest_bodies = DeadBody.query.order_by(DeadBody.body_id.desc()).limit(25).all()
    pending_claims = ClaimRequest.query.filter_by(status="Pending").order_by(ClaimRequest.claim_id.desc()).all()
    user_claims = []
    pending_claim_body_ids = set()
    user_claim_body_ids = set()
    if role == "Public":
        user_claims = (
            ClaimRequest.query.filter_by(claimant_email=mail)
            .order_by(ClaimRequest.claim_id.desc())
            .all()
        )
        if latest_bodies:
            body_ids = [body.body_id for body in latest_bodies]
            pending_claim_body_ids = {
                row[0]
                for row in db.session.query(ClaimRequest.body_id)
                .filter(ClaimRequest.body_id.in_(body_ids), ClaimRequest.status == "Pending")
                .all()
            }
            user_claim_body_ids = {
                row[0]
                for row in db.session.query(ClaimRequest.body_id)
                .filter(
                    ClaimRequest.body_id.in_(body_ids),
                    ClaimRequest.claimant_email == mail,
                )
                .all()
            }
    users = []
    if role == "Admin":
        users = db.session.query(User, Role.rolename).join(Role, User.fk_r_id == Role.r_id).order_by(User.u_id.desc()).all()

    return render_template(
        "dashboard.html",
        role=role,
        mail=mail,
        total_bodies=DeadBody.query.count(),
        unclaimed=DeadBody.query.filter_by(status="Unclaimed").count(),
        claimed=DeadBody.query.filter_by(status="Claimed").count(),
        cremated=DeadBody.query.filter_by(status="Cremated").count(),
        latest_bodies=latest_bodies,
        pending_claims=pending_claims,
        user_claims=user_claims,
        pending_claim_body_ids=pending_claim_body_ids,
        user_claim_body_ids=user_claim_body_ids,
        users=users,
    )


@app.route("/add_body", methods=["GET", "POST"])
@role_required("Admin", "Nurse", "Police")
def add_body():
    if request.method == "GET":
        return render_template("add_body.html")

    gender = request.form.get("gender", "").strip()
    age = request.form.get("age", "").strip()
    height = request.form.get("height", "").strip()
    body_build = request.form.get("body_build", "").strip()
    complexion = request.form.get("complexion", "").strip()
    marks = request.form.get("marks", "").strip()
    clothing = request.form.get("clothing", "").strip()
    teeth = request.form.get("teeth", "").strip()
    dental_notes = request.form.get("dental_notes", "").strip()
    found_location = request.form.get("found_location", "").strip()
    found_date = request.form.get("date_found", "").strip()

    if not gender or not found_location:
        flash("Gender and found location are required.", "error")
        return redirect(url_for("add_body"))

    try:
        approx_age = parse_optional_int(age, "Age", 0, 130)
        missing_teeth = parse_optional_int(teeth, "Missing teeth", 0, 32)
        date_found = parse_found_date(found_date)
    except ValueError as exc:
        flash(str(exc), "error")
        return redirect(url_for("add_body"))

    db.session.add(
        DeadBody(
            tag_number=generate_tag_number(),
            gender=gender,
            approx_age=approx_age,
            height=height,
            body_build=body_build,
            complexion=complexion,
            identifying_marks=marks,
            clothing_description=clothing,
            missing_teeth=missing_teeth,
            dental_notes=dental_notes,
            date_found=date_found,
            found_location=found_location,
            registered_by=session.get("u_email", "system"),
            status="Unclaimed",
        )
    )
    db.session.commit()
    flash("Body record added successfully.", "success")
    return redirect(url_for("dashboard_page"))


@app.route("/create_user", methods=["POST"])
@role_required("Admin")
def create_user():
    new_email = request.form.get("u_email", "").strip()
    new_password = request.form.get("u_password", "").strip()
    role_name = request.form.get("role_name", "").strip()

    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", new_email):
        flash("Enter a valid email for the new user.", "error")
        return redirect(url_for("dashboard_page"))
    if len(new_password) < 8:
        flash("New user password must be at least 8 characters.", "error")
        return redirect(url_for("dashboard_page"))
    if role_name not in {"Admin", "Nurse", "Police"}:
        flash("Only Admin/Nurse/Police roles can be created here.", "error")
        return redirect(url_for("dashboard_page"))
    if User.query.filter_by(u_email=new_email).first():
        flash("This email already exists.", "error")
        return redirect(url_for("dashboard_page"))

    role_id = role_id_by_name(role_name)
    if not role_id:
        flash("Selected role not found in DB.", "error")
        return redirect(url_for("dashboard_page"))

    db.session.add(
        User(
            u_email=new_email,
            u_password=generate_password_hash(new_password),
            fk_r_id=role_id,
        )
    )
    db.session.commit()
    flash(f"{role_name} user created successfully.", "success")
    return redirect(url_for("dashboard_page"))


@app.route("/search_body", methods=["GET"])
def search_body():
    age = request.args.get("age", "").strip()
    status = request.args.get("status", "").strip()
    teeth = request.args.get("teeth", "").strip()

    query = DeadBody.query
    if age:
        try:
            min_age = parse_optional_int(age, "Age", 0, 130)
            if min_age is not None:
                query = query.filter(DeadBody.approx_age >= min_age)
        except ValueError:
            flash("Invalid age filter ignored.", "error")
    if status:
        if status in {"Unclaimed", "Claimed", "Cremated"}:
            query = query.filter_by(status=status)
        else:
            flash("Invalid status filter ignored.", "error")
    if teeth:
        try:
            missing_teeth = parse_optional_int(teeth, "Missing teeth", 0, 32)
            if missing_teeth is not None:
                query = query.filter_by(missing_teeth=missing_teeth)
        except ValueError:
            flash("Invalid missing teeth filter ignored.", "error")

    results = query.order_by(DeadBody.body_id.desc()).all()
    pending_claim_body_ids = set()
    user_claim_body_ids = set()
    role = current_role_name()

    if results:
        body_ids = [body.body_id for body in results]
        pending_claim_body_ids = {
            row[0]
            for row in db.session.query(ClaimRequest.body_id)
            .filter(ClaimRequest.body_id.in_(body_ids), ClaimRequest.status == "Pending")
            .all()
        }
        if role == "Public" and session.get("u_email"):
            user_claim_body_ids = {
                row[0]
                for row in db.session.query(ClaimRequest.body_id)
                .filter(
                    ClaimRequest.body_id.in_(body_ids),
                    ClaimRequest.claimant_email == session.get("u_email"),
                )
                .all()
            }

    return render_template(
        "search_body.html",
        results=results,
        selected_status=status,
        pending_claim_body_ids=pending_claim_body_ids,
        user_claim_body_ids=user_claim_body_ids,
        role=role,
    )


@app.route("/body/<int:body_id>")
def body_detail(body_id):
    record = DeadBody.query.get_or_404(body_id)
    claims = ClaimRequest.query.filter_by(body_id=body_id).order_by(ClaimRequest.claim_id.desc()).all()
    role = current_role_name()
    user_has_claimed = False
    pending_claim_exists = any(claim.status == "Pending" for claim in claims)
    if role == "Public" and session.get("u_email"):
        user_has_claimed = any(claim.claimant_email == session.get("u_email") for claim in claims)

    return render_template(
        "body_detail.html",
        record=record,
        claims=claims,
        role=role,
        pending_claim_exists=pending_claim_exists,
        user_has_claimed=user_has_claimed,
    )


@app.route("/edit_body/<int:body_id>", methods=["GET", "POST"])
@role_required("Admin")
def edit_body(body_id):
    record = DeadBody.query.get_or_404(body_id)
    if request.method == "GET":
        return render_template("edit_body.html", record=record)

    gender = request.form.get("gender", "").strip()
    age = request.form.get("age", "").strip()
    height = request.form.get("height", "").strip()
    body_build = request.form.get("body_build", "").strip()
    complexion = request.form.get("complexion", "").strip()
    marks = request.form.get("marks", "").strip()
    clothing = request.form.get("clothing", "").strip()
    teeth = request.form.get("teeth", "").strip()
    dental_notes = request.form.get("dental_notes", "").strip()
    found_location = request.form.get("found_location", "").strip()
    found_date = request.form.get("date_found", "").strip()
    status = request.form.get("status", "").strip()
    death_certificate = request.form.get("death_certificate", "").strip()

    if not gender or not found_location:
        flash("Gender and found location are required.", "error")
        return redirect(url_for("edit_body", body_id=body_id))
    if status not in {"Unclaimed", "Claimed", "Cremated"}:
        flash("Invalid status value.", "error")
        return redirect(url_for("edit_body", body_id=body_id))

    try:
        approx_age = parse_optional_int(age, "Age", 0, 130)
        missing_teeth = parse_optional_int(teeth, "Missing teeth", 0, 32)
        date_found = parse_found_date(found_date)
    except ValueError as exc:
        flash(str(exc), "error")
        return redirect(url_for("edit_body", body_id=body_id))

    record.gender = gender
    record.approx_age = approx_age
    record.height = height
    record.body_build = body_build
    record.complexion = complexion
    record.identifying_marks = marks
    record.clothing_description = clothing
    record.missing_teeth = missing_teeth
    record.dental_notes = dental_notes
    record.found_location = found_location
    record.date_found = date_found
    record.status = status
    record.death_certificate = death_certificate
    record.cremation_date = date.today() if status == "Cremated" else None

    db.session.commit()
    flash("Body record updated successfully.", "success")
    return redirect(url_for("dashboard_page"))


@app.route("/claim/<int:body_id>", methods=["GET", "POST"])
def submit_claim(body_id):
    body = DeadBody.query.get_or_404(body_id)
    role = current_role_name()

    if not session.get("u_id"):
        flash("Login is required to submit a claim.", "error")
        return redirect(url_for("login", next=url_for("submit_claim", body_id=body_id)))

    if role != "Public":
        flash("Only public users can submit claims.", "error")
        return redirect(url_for("dashboard_page"))

    claims = ClaimRequest.query.filter_by(body_id=body_id).order_by(ClaimRequest.claim_id.desc()).all()
    pending_claim_exists = any(claim.status == "Pending" for claim in claims)
    user_has_claimed = any(claim.claimant_email == session.get("u_email") for claim in claims)

    if request.method == "GET":
        return render_template(
            "claim_body.html",
            record=body,
            pending_claim_exists=pending_claim_exists,
            user_has_claimed=user_has_claimed,
        )

    if body.status != "Unclaimed":
        flash("Claims can only be submitted for unclaimed records.", "error")
        return redirect(url_for("submit_claim", body_id=body_id))

    claimant_name = request.form.get("claimant_name", "").strip()
    claimant_phone = request.form.get("claimant_phone", "").strip()
    claimant_relation = request.form.get("claimant_relation", "").strip()

    if not claimant_name or not claimant_phone or not claimant_relation:
        flash("All claim fields are required.", "error")
        return redirect(url_for("submit_claim", body_id=body_id))
    if not re.match(r"^[0-9+\-\s]{7,20}$", claimant_phone):
        flash("Phone number format is invalid.", "error")
        return redirect(url_for("submit_claim", body_id=body_id))
    claimant_email = session.get("u_email", "").strip()
    existing_pending_claim = ClaimRequest.query.filter_by(body_id=body_id, status="Pending").first()
    if existing_pending_claim:
        flash("A pending claim already exists for this body.", "error")
        return redirect(url_for("submit_claim", body_id=body_id))
    existing_user_claim = ClaimRequest.query.filter_by(body_id=body_id, claimant_email=claimant_email).first()
    if existing_user_claim:
        flash("You have already submitted a claim for this body.", "error")
        return redirect(url_for("submit_claim", body_id=body_id))

    db.session.add(
        ClaimRequest(
            body_id=body_id,
            claimant_name=claimant_name,
            claimant_email=claimant_email,
            claimant_phone=claimant_phone,
            claimant_relation=claimant_relation,
            status="Pending",
        )
    )
    db.session.commit()
    flash("Claim submitted successfully.", "success")
    return redirect(url_for("dashboard_page"))


@app.route("/review_claim/<int:claim_id>/<decision>", methods=["POST"])
@role_required("Admin")
def review_claim(claim_id, decision):
    claim = ClaimRequest.query.get_or_404(claim_id)
    body = DeadBody.query.get(claim.body_id)

    if decision not in {"approve", "reject"}:
        flash("Invalid review decision.", "error")
        return redirect(url_for("dashboard_page"))

    if claim.status != "Pending":
        flash("This claim has already been reviewed.", "error")
        return redirect(url_for("dashboard_page"))

    note = request.form.get("review_note", "").strip()
    claim.status = "Approved" if decision == "approve" else "Rejected"
    claim.reviewed_by = session.get("u_email", "reviewer")
    claim.review_note = note

    if decision == "approve" and body:
        body.status = "Claimed"
        ClaimRequest.query.filter(
            ClaimRequest.body_id == body.body_id,
            ClaimRequest.claim_id != claim.claim_id,
            ClaimRequest.status == "Pending",
        ).update(
            {
                ClaimRequest.status: "Rejected",
                ClaimRequest.reviewed_by: session.get("u_email", "reviewer"),
                ClaimRequest.review_note: f"Automatically rejected after claim #{claim.claim_id} approval.",
            },
            synchronize_session=False,
        )

    db.session.commit()
    flash(f"Claim {decision}d.", "success")
    return redirect(url_for("dashboard_page"))


@app.route("/mark_cremated/<int:body_id>", methods=["POST"])
@role_required("Admin", "Nurse", "Police")
def mark_cremated(body_id):
    body = DeadBody.query.get_or_404(body_id)
    if body.status != "Cremated":
        body.status = "Cremated"
        body.cremation_date = date.today()
        body.death_certificate = request.form.get("death_certificate", "").strip()
        db.session.commit()
        flash("Body status updated to cremated.", "success")
    else:
        flash("Body is already marked as cremated.", "error")
    return redirect(url_for("dashboard_page"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home_page"))


with app.app_context():
    db.create_all()
    inspector = db.inspect(db.engine)
    claim_request_columns = {column["name"] for column in inspector.get_columns("claim_request")} if inspector.has_table("claim_request") else set()
    if "claimant_email" not in claim_request_columns:
        with db.engine.begin() as connection:
            connection.exec_driver_sql("ALTER TABLE claim_request ADD COLUMN claimant_email VARCHAR(120) NOT NULL DEFAULT ''")
            connection.exec_driver_sql(
                "UPDATE claim_request SET claimant_email = '' WHERE claimant_email IS NULL"
            )
    ensure_seed_data()


if __name__ == "__main__":
    with app.app_context():
        ensure_seed_data()

    app.run(debug=True)
