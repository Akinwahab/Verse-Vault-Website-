from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy import Integer, String, Text, DateTime, ForeignKey
from flask_ckeditor import CKEditor
from datetime import date, datetime
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from flask_bootstrap import Bootstrap5
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm

# --- App setup ---
app = Flask(__name__)
app.config['SECRET_KEY'] = "4z3c8e7a1b0d5a9k8f62b7c9f3c9e1o5"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'
ckeditor = CKEditor(app)
Bootstrap5(app)

# --- Database setup ---
class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)
db.init_app(app)

# --- Login manager setup ---
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id)) if user_id.isdigit() else None

# --- Models ---
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(100))
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    author_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"))
    author = relationship("User", back_populates="posts")
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)
    comments = relationship("Comment", back_populates="parent_post")

class Comment(db.Model):
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    text: Mapped[str] = mapped_column(Text, nullable=False)
    author_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"))
    comment_author = relationship("User", back_populates="comments")
    post_id: Mapped[int] = mapped_column(Integer, ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")

with app.app_context():
    db.create_all()

# --- Helpers ---
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function

@app.context_processor
def inject_year():
    return {"year": datetime.now().year}

# --- Routes ---
@app.route('/')
@app.route('/page/<int:page>')
def home(page=1):
    per_page = 5
    posts = db.session.scalars(
        db.select(BlogPost).order_by(BlogPost.date.desc())
        .offset((page-1)*per_page).limit(per_page)
    ).all()

    # Check if there is a next page
    total_posts = db.session.scalar(db.select(db.func.count(BlogPost.id)))
    has_next = page * per_page < total_posts

    return render_template(
        "index.html",
        all_posts=posts,
        current_user=current_user,
        page=page,
        has_next=has_next
    )


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        user = db.session.scalar(db.select(User).where(User.email == form.email.data))
        if user:
            flash("This lantern has already been lit with that email. Step instead into login.")
            return redirect(url_for('login'))

        new_user = User(
            email=form.email.data,
            name=form.name.data,
            password=generate_password_hash(form.password.data, method='pbkdf2:sha256', salt_length=8),
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for("home"))
    return render_template("register.html", form=form, current_user=current_user)

@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = db.session.scalar(db.select(User).where(User.email == form.email.data))
        if not user:
            flash("That address is unknown to this vault. Try again, or carve a new path through registration.")
            return redirect(url_for('login'))
        if not check_password_hash(user.password, form.password.data):
            flash("The key you pressed does not fit the lock. Try again with the true phrase.")
            return redirect(url_for('login'))

        login_user(user)
        return redirect(url_for('home'))
    return render_template("login.html", form=form, current_user=current_user)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = db.get_or_404(BlogPost, post_id)
    comment_form = CommentForm()
    if comment_form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("Only those with a name may leave their echo here. Log in or register first.")
            return redirect(url_for("login"))
        new_comment = Comment(
            text=comment_form.comment_text.data,
            comment_author=current_user,
            parent_post=requested_post
        )
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for("show_post", post_id=post_id))
    return render_template("post.html", post=requested_post, form=comment_form, current_user=current_user)

@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
        )
        db.session.add(new_post)
        db.session.commit()
        flash("A fresh stanza has been placed upon the shelf.")
        return redirect(url_for("home"))
    return render_template("make-post.html", form=form, current_user=current_user)

@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body
    )
    if form.validate_on_submit():
        post.title = form.title.data
        post.subtitle = form.subtitle.data
        post.img_url = form.img_url.data
        post.body = form.body.data
        db.session.commit()
        flash("The lines have been rewritten, and the page breathes anew.")
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=form, is_edit=True, current_user=current_user)

@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    db.session.delete(post)
    db.session.commit()
    flash("One verse has been removed, fading like smoke into memory.")
    return redirect(url_for("home"))

@app.route('/about')
def about():
    return render_template('about.html', current_user=current_user)

# --- Error Handlers ---
@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404

@app.errorhandler(403)
def forbidden(e):
    return render_template("403.html"), 403

# --- Run ---
if __name__ == "__main__":
    app.run(debug=True)
