from flask import Flask, render_template, request, redirect, url_for, flash
#FOR LOGIN AUTHENTICATION
from flask_login import LoginManager, UserMixin, login_required, logout_user, login_user, current_user
#FOR DATABASE
from flask_sqlalchemy import SQLAlchemy
#for ONE TO MANY RELATIONSHIP
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
#FOR CREATING FORMS
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL
#FOR EDITING BLOG PAGE CKEDITOR
from flask_ckeditor import CKEditor, CKEditorField
#FOR PASSWORD HASHING
from werkzeug.security import generate_password_hash, check_password_hash
#import requests
import datetime
import smtplib
import os

MY_MAIL = os.environ.get("EMAIL")
PASS = os.environ.get("PASSWORD")

#initializing fllask app
app = Flask(__name__)

#initializing database
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///posts.db"
# app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///user.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
#initializing ckeditor
ckeditor = CKEditor(app)

#secret key for flask form
app.secret_key = 'secretkey'

#initializing login manager
login_manager = LoginManager()
login_manager.init_app(app)

#to get return object
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


#User table creation (Parent Table)
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(100))
    #this will acts like a list of BlogPost objects attached to each User
    #the author reffers to the author property of BlogPost class
    #acts as child relationship
    posts = relationship("BlogPost", back_populates="author")
    #comment_author reffers to an comment_author property in comment class
    comments = relationship("Comment", back_populates="comment_author")


#database table creation (Child Table)
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    #creates foreign key , "users.id" the users reffers to the tablename User
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    #creates reference to the User object , the "posts" refers to the posts property in the User class
    author = relationship("User", back_populates="posts")

    title = db.Column(db.String(250), unique=True, nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    #******************* parent relationship with comments#
    comments = relationship("Comment", back_populates="parent_post")



class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    comment_author = relationship("User", back_populates="comments")
#******************************* Child relationship *******************#
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")
    text = db.Column(db.Text, nullable=False)

# #creating table
with app.app_context():
    db.create_all()

#creating form using flask_wtf
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    author = StringField("Your Name", validators=[DataRequired()])
    img_url = StringField("Blog Image Url", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


#creating login form
class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("password", validators=[DataRequired()])
    submit = SubmitField("Log me in")

#creating registration form
class RegisterForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("password", validators=[DataRequired()])
    submit = SubmitField("Sign up")

class Comments(FlaskForm):
    comment_text = CKEditorField("Commments", validators=[DataRequired()])
    submit = SubmitField("Submit Comment")

# response = requests.get("https://api.npoint.io/06c78c601263dd775a60")
# response_data = response.json()
# print(response_data)

response_data = ""

@app.route('/')
def homepage():
    print("running homepage")
    response_data = db.session.query(BlogPost).all() #this is object of blog_post
    #name = current_user.name #current_user is object of user this works only when u logged in
    # print(response_data)
    # for post in response_data:
    #     print(post.author_id)


    return render_template("index.html", blog=response_data, logged_in=current_user.is_authenticated)


#when clicked on blog show full blog
@app.route('/blog/<num>', methods=['GET', 'POST'])
def get_blog(num):
    form = Comments()
    response_data = BlogPost.query.get(num)
    if request.method == "POST":
        if not current_user.is_authenticated:
            flash("you need to login or register to comment.")
            return redirect(url_for("login"))
        new_comment = Comment(
            text=form.comment_text.data,
            comment_author=current_user,
            parent_post=response_data
        )
        db.session.add(new_comment)
        db.session.commit()
    return render_template('blog.html', num=num, blog1=response_data, form=form, logged_in=current_user.is_authenticated)


#registration page for new user
@app.route('/register', methods=['GET', 'POST'])
def register():
    register_form = RegisterForm()
    if request.method == 'POST':
        #if user has already an account
        if User.query.filter_by(email=request.form.get('email')).first():
            flash("This email already exist!!! try log in.")
            return redirect(url_for("login"))

        hashed_password = generate_password_hash(
            password=register_form.password.data,
            method='pbkdf2:sha256',
            salt_length=8
        )
        #print(register_form.email.data, register_form.name.data, hashed_password)
        new_user = User(
            email=register_form.email.data,
            name=register_form.name.data,
            password=hashed_password
        )
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for("login"))
    return render_template('register.html', form=register_form, logged_in=current_user.is_authenticated)


#login page for new user
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    print('in log in page')
    if form.validate_on_submit():
        # getting details to check the validation
        email = form.email.data
        password = form.password.data

        #checking if email exist or not in database
        user = User.query.filter_by(email=email).first()
        if not user:
            flash("Email does not exist! please try again.")
            return redirect(url_for('login'))

        #checkinng for password
        elif not check_password_hash(user.password, password):
            flash("Incorrect password!! try again.")
            return redirect(url_for('login'))

        else:
            login_user(user)
            return redirect(url_for("homepage"))
    return render_template("login.html", form=form, logged_in=current_user.is_authenticated)


#Creating new blog using post
@app.route('/new-post', methods=['GET', 'POST'])
@login_required
def new_post():
    create_post_form = CreatePostForm()
    if request.method == 'POST':
        title = request.form.get('title')
        body = request.form.get('body')         #current_user is object of User
        img_url = request.form.get('img_url')
        date = datetime.datetime.now()
        today_date = date.strftime('%B %d, %Y')
        author = current_user
        print(title, body, img_url)
        new_blog = BlogPost(title=title, body=body, author=author, img_url=img_url, date=today_date)
        db.session.add(new_blog)
        db.session.commit()
        return redirect(url_for('homepage'))
    return render_template('make-post.html', form=create_post_form, logged_in=current_user.is_authenticated)


#edit the blog and update

@app.route('/edit-post/<int:id>', methods=['GET', 'POST'])
@login_required
def edit(id):
    post = BlogPost.query.get(id)
    if post.author_id == current_user.id:
        edit_form = CreatePostForm(
            title=post.title,
            img_url=post.img_url,
            author=current_user.name,
            body=post.body
        )
        if request.method == 'POST':
            post.title = edit_form.title.data
            post.img_url = edit_form.img_url.data
            post.author = current_user
            post.body = edit_form.body.data
            db.session.commit()
            return redirect(url_for('get_blog', num=post.id))
        return render_template('edit.html', form=edit_form, is_edit=True, posts=post, logged_in=current_user.is_authenticated)
    return redirect(url_for('get_blog', num=post.id))

#to delete the blog
@app.route('/delete')
@login_required
def delete():
    id = request.args.get('id')
    post = BlogPost.query.get(id)
    if current_user.id == post.author_id:
        post_to_delete = BlogPost.query.get(id)
        db.session.delete(post_to_delete)
        db.session.commit()
        return redirect(url_for('homepage', logged_in=current_user.is_authenticated))
    flash("You are not authorized to delete this post!!!")
    return redirect(url_for('homepage', logged_in=current_user.is_authenticated))

#contact us page
@app.route('/contact', methods=['GET', 'POST'])
@login_required
def contact():
    if request.method == 'POST':
        data = request.form
        with smtplib.SMTP("smtp.gmail.com", 587) as connection:
            connection.starttls()
            connection.login(user=MY_MAIL, password=PASS)
            connection.sendmail(
                from_addr=data.get("email"),
                to_addrs=MY_MAIL,
                msg=f'Subject:mail from my_blogg by user {data.get("name")}\n\nName: {data["name"]}\nNumber: {data["number"]}'
                    f'\nEmail: {data.get("email")}'
                    f'\nMsg: {data["message"]}'
            )
        return render_template('contact.html', msg_sent=True)
    return render_template('contact.html', msg_sent=False, logged_in=current_user.is_authenticated)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for("homepage"))

if __name__ == "__main__":
    app.run(debug=True)