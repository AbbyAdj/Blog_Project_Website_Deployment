# READ BEFORE STARTING
# The code below needs a lot of improvements
# Look for an alternative to the CKEditor, it stores the comments in HTML form, I don't like that.
# For the flashing, I tried to change the text to red, it didn't work.


from __future__ import annotations

from hashlib import md5
from typing import List
import os
from dotenv import load_dotenv
from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash, request
from flask_migrate import Migrate
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text, ForeignKey
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
# Import your forms from the forms.py
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm


'''
Make sure the required packages are installed: 
Open the Terminal in PyCharm (bottom left). 

On Windows type:
python -m pip install -r requirements.txt

On MacOS type:
pip3 install -r requirements.txt

This will install the packages from the requirements.txt for this project.
'''

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("FLASK_KEY")
ckeditor = CKEditor(app)
Bootstrap5(app)


# FLASK LOGIN CONFIGURATION
login_manager = LoginManager()
login_manager.login_message = "login"
login_manager.init_app(app)


# CREATE DATABASE
class Base(DeclarativeBase):
    pass
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URI",'sqlite:///posts.db')
db = SQLAlchemy(model_class=Base)
db.init_app(app)
migrate = Migrate(app, db, command="migrate")


# CONFIGURE TABLES
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    email = db.Column(db.String, unique=True, nullable=False)
    password = db.Column(db.String, unique=True, nullable=False)
    posts = db.relationship("BlogPost", back_populates="author")
    comments = db.relationship("Comment", back_populates="author")

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    author= db.relationship("User", back_populates="posts")
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)
    comments = db.relationship("Comment", back_populates="parent_post")

class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    author = db.relationship("User", back_populates="comments")
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = db.relationship("BlogPost", back_populates="comments")
    text = db.Column(db.Text, nullable=False)



with app.app_context():
    db.create_all()

# CREATE DECORATORS
def admin_only(func):
    """Makes sure that only the admin can access the decorated routes"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        admin = db.session.execute(db.select(User).where(User.id == 1)).scalar()
        user = db.session.execute(db.select(User).where(User.id == current_user.id)).scalar()
        if admin == user:
            return func
        else:
            abort(403)
    return wrapper

def admin_access(func):
    """Grants other users admin access when specified."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        admin = db.session.execute(db.select(User).where(User.id == 2)).scalar()
        user = db.session.execute(db.select(User).where(User.id == current_user.id)).scalar()
        if admin == user:
            return func
        else:
            abort(403)
    return wrapper

# OTHER METHODS
def check_admin():
    """Checking if logged in user is the admin"""
    is_admin = False
    admin = db.session.execute(db.select(User).where(User.id == 1)).scalar()
    if current_user.is_authenticated:
        user = db.session.execute(db.select(User).where(User.id == current_user.id)).scalar()
        if admin == user:
            is_admin = True
    return is_admin

def gravatar_url(email, size=100, rating='g', default='retro', force_default=False):
    """Gravatar image"""
    hash_value = md5(email.lower().encode('utf-8')).hexdigest()
    return f"https://www.gravatar.com/avatar/{hash_value}?s={size}&d={default}&r={rating}&f={force_default}"



@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        name = request.form.get("name")
        email = request.form.get("email")
        password = request.form.get("password")
        user_already_exists = db.session.execute(db.select(User).where(User.email==email)).scalar()
        if user_already_exists:
            flash("Email has already been registered")
            return redirect(url_for("register"))
        password_hash = generate_password_hash(password=password, method="pbkdf2:sha256:600000", salt_length=10)
        new_user = User(
            name=name,
            email=email,
            password=password_hash
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        flash("You have been successfully registered")
        return redirect(url_for("get_all_posts"))
    return render_template("register.html", form=form)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = request.form.get("email")
        password = request.form.get("password")
        user = db.session.execute(db.select(User).where(User.email==email)).scalar()
        if user:
            is_password_correct = check_password_hash(pwhash=user.password, password=password)
            if is_password_correct:
                login_user(user)
                flash("You have been logged in successfully")
                return redirect(url_for("get_all_posts"))
        else:
            flash("Invalid credentials")
            return redirect(url_for("login"))
    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    users = db.session.execute(db.select(User)).scalars().all()
    is_admin = check_admin()
    return render_template("index.html", all_posts=posts[::-1], users=users, is_admin=is_admin)


# TODO: Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>", methods =["GET", "POST"])
def show_post(post_id):
    requested_post = db.get_or_404(BlogPost, post_id)
    form = CommentForm()
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to register or login to comment")
            return redirect(url_for("login"))
        new_comment = Comment(
            author = current_user,
            parent_post = requested_post,
            text = form.body.data
        )
        db.session.add(new_comment)
        db.session.commit()
        return redirect(request.url)
    is_admin = check_admin()
    comments = db.session.execute(db.select(Comment).where(Comment.post_id == post_id)).scalars().all()

    return render_template("post.html",
                           post=requested_post,
                           is_admin=is_admin,
                           comments=comments,
                           form=form,
                           gravatar_url=gravatar_url)


# TODO: Use a decorator so only an admin user can create a new post
@admin_only
@admin_access
@app.route("/new-post", methods=["GET", "POST"])

def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


# TODO: Use a decorator so only an admin user can edit a post
@admin_only
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True)


# TODO: Use a decorator so only an admin user can delete a post
@admin_only
@app.route("/delete/<int:post_id>")
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


if __name__ == "__main__":
    app.run(debug=True, port=5002)
