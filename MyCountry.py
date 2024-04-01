from flask import Flask, render_template, redirect, logging, url_for, session, request, flash
from flask_login import login_user, logout_user, current_user, login_required, LoginManager
from flask_sqlalchemy import SQLAlchemy
from wtforms import Form, StringField, TextAreaField, PasswordField, validators, IntegerField
import os
from werkzeug.utils import secure_filename

from passlib.hash import sha256_crypt
from functools import wraps

app = Flask(__name__)

APP_ROOT = os.path.dirname(os.path.abspath(__file__))

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mycountry.sqlite3'
app.config['SECRET_KEY'] = "random string"
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


@app.route('/')
# @login_required
def home():
    return render_template('home.html')


class Page(db.Model):
    id = db.Column('page_id', db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    pcomments = db.Column(db.String(300))
    pages = db.Column(db.String(25))

    def __init__(self, name, pcomments, pages):
        self.name = name
        self.pcomments = pcomments
        self.pages = pages


class PageForm(Form):
    comment = TextAreaField('Add Comment', [validators.Length(min=1)])


class Guest(db.Model):
    id = db.Column('guest_id', db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(50))
    contact = db.Column(db.String(20))
    comments = db.Column(db.String(300))

    def __init__(self, name, email, contact, comments):
        self.name = name
        self.email = email
        self.contact = contact
        self.comments = comments


class GuestForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=50)])
    email = StringField('Email', [validators.Length(min=6, max=50)])
    contact = IntegerField('Contact', [validators.number_range(min=0, max=999999999999999)])
    comments = StringField('Comments', [validators.Length(min=1, max=300)])


@app.route('/guest', methods=['GET', 'POST'])
def guest():
    form = GuestForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        contact = form.contact.data
        comments = form.comments.data

        guest = Guest(name, email, contact, comments)
        db.session.add(guest)
        db.session.commit()

    return render_template('guest.html', form=form, guest=Guest.query.all())


# @app.route('/show_guest')
# def show_guest():
# return render_template('include/show_guest.html' , guest = Guest.query.all())


class User(db.Model):
    id = db.Column('student_id', db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(50))
    username = db.Column(db.String(200))
    password = db.Column(db.String(20))

    def __init__(self, name, email, username, password):
        self.name = name
        self.email = email
        self.username = username
        self.password = password

    @property
    def is_active(self):
        return True

    def get_id(self):
        """Return the email address to satisfy Flask-Login's requirements."""
        return self.id

    def is_authenticated(self):
        """Return True if the user is authenticated."""
        return True

    def is_anonymous(self):
        """False, as anonymous users aren't supported."""
        return False


class RegisterForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=50)])
    username = StringField('Username', [validators.Length(min=4, max=25)])
    email = StringField('Email', [validators.Length(min=6, max=50)])
    password = PasswordField('Password', [validators.DataRequired(),
                                          validators.EqualTo('confirm', message='Password do not match')])
    confirm = PasswordField('Confirm Password')


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))
        user = User(name, email, username, password)
        db.session.add(user)
        db.session.commit()

        flash('You are now register', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)


# user login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        registered_user = User.query.filter_by(username=username).first()
        if registered_user is None or not sha256_crypt.verify(password, registered_user.password):
            flash('Username or Password is invalid', 'error')
            return redirect(url_for('login'))
        login_user(registered_user)
        flash('Logged in successfully', 'success')
        return redirect(request.args.get('next') or url_for('dashboard'))
    return render_template('login.html')


@login_manager.user_loader
def load_user(user_id):
    return User.query.filter_by(id=user_id).first()


class Article(db.Model):
    id = db.Column('article_id', db.Integer, primary_key=True)
    title = db.Column(db.String(255))
    author = db.Column(db.String(100))
    body = db.Column(db.TEXT())

    def __init__(self, title, author, body):
        self.title = title
        self.author = author
        self.body = body


# ArticleForm Class
class ArticleForm(Form):
    title = StringField('Title', [validators.Length(min=1, max=200)])
    body = TextAreaField('Body', [validators.Length(min=1)])


@app.route('/add_article', methods=['GET', 'POST'])
@login_required
def add_articles():
    form = ArticleForm(request.form)
    if request.method == 'POST' and form.validate():
        title = form.title.data
        author = current_user.username
        body = form.body.data

        article = Article(title, author, body)
        db.session.add(article)
        db.session.commit()
        flash('Article Created', 'success')
        return redirect(url_for('dashboard'))

    return render_template('add_article.html', form=form)


@app.route('/delete_article/<string:id>', methods=['POST'])
@login_required
def delete_article(id):
    article = Article.query.filter_by(id=id).first()
    db.session.delete(article)
    db.session.commit()
    flash('Article Deleted', 'success')
    return redirect(url_for('dashboard'))


@app.route('/articles')
def articles():
    return render_template('articles.html', articles=Article.query.all())


@app.route('/article/<string:id>/')
def article(id):
    article = Article.query.filter_by(id=id).first()
    return render_template('article.html', article=article)


@app.route('/dashboard')
@login_required
def dashboard():
    name = current_user.username
    return render_template('dashboard.html', article=Article.query.all(), username=name)


# log out
@app.route('/logout')
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))


@app.route('/history')
def history():
    return render_template('history.html')


@app.route('/lahore')
def lahore():
    return render_template('lahore.html')


@app.route('/dishes')
def dishes():
    return render_template('dishes.html')


@app.route('/attraction')
def attraction():
    return render_template('attraction.html')


@app.route('/culture')
def culture():
    return render_template('culture.html')


# ---------------------------------------------------------------------#

@app.route('/minar', methods=['GET', 'POST'])
@login_required
def minar():
    form = PageForm(request.form)
    if request.method == 'POST' and form.validate():
        name = current_user.username
        comment = form.comment.data

        comment = Page(name, comment, 'minar')
        db.session.add(comment)
        db.session.commit()
        flash('Comments Added', 'success')
        return redirect('minar')

    return render_template('minar.html', form=form, page=Page.query.filter_by(pages='minar'))


@app.route('/islam', methods=['GET', 'POST'])
@login_required
def islam():
    form = PageForm(request.form)
    if request.method == 'POST' and form.validate():
        name = current_user.username
        comment = form.comment.data

        comment = Page(name, comment, 'islam')
        db.session.add(comment)
        db.session.commit()
        flash('Comments Added', 'success')
        return redirect('islam')

    return render_template('islam.html', form=form, page=Page.query.filter_by(pages='islam'))


@app.route('/social', methods=['GET', 'POST'])
@login_required
def social():
    form = PageForm(request.form)
    if request.method == 'POST' and form.validate():
        name = current_user.username
        comment = form.comment.data

        comment = Page(name, comment, 'social')
        db.session.add(comment)
        db.session.commit()
        flash('Comments Added', 'success')
        return redirect('social')

    return render_template('social.html', form=form, page=Page.query.filter_by(pages='social'))


@app.route('/dress', methods=['GET', 'POST'])
@login_required
def dress():
    form = PageForm(request.form)
    if request.method == 'POST' and form.validate():
        name = current_user.username
        comment = form.comment.data

        comment = Page(name, comment, 'dress')
        db.session.add(comment)
        db.session.commit()
        flash('Comments Added', 'success')
        return redirect('dress')

    return render_template('dress.html', form=form, page=Page.query.filter_by(pages='dress'))


@app.route('/kabab', methods=['GET', 'POST'])
@login_required
def kabab():
    form = PageForm(request.form)
    if request.method == 'POST' and form.validate():
        name = current_user.username
        comment = form.comment.data

        comment = Page(name, comment, 'kabab')
        db.session.add(comment)
        db.session.commit()
        flash('Comments Added', 'success')
        return redirect('kabab')

    return render_template('kabab.html', form=form, page=Page.query.filter_by(pages='kabab'))


@app.route('/karhai', methods=['GET', 'POST'])
@login_required
def karhai():
    form = PageForm(request.form)
    if request.method == 'POST' and form.validate():
        name = current_user.username
        comment = form.comment.data

        comment = Page(name, comment, 'karhai')
        db.session.add(comment)
        db.session.commit()
        flash('Comments Added', 'success')
        return redirect('karhai')

    return render_template('karhai.html', form=form, page=Page.query.filter_by(pages='karhai'))


@app.route('/biryani', methods=['GET', 'POST'])
@login_required
def biryani():
    form = PageForm(request.form)
    if request.method == 'POST' and form.validate():
        name = current_user.username
        comment = form.comment.data

        comment = Page(name, comment, 'biryani')
        db.session.add(comment)
        db.session.commit()
        flash('Comments Added', 'success')
        return redirect('biryani')

    return render_template('biryani.html', form=form, page=Page.query.filter_by(pages='biryani'))


@app.route('/badshah', methods=['GET', 'POST'])
@login_required
def badshah():
    form = PageForm(request.form)
    if request.method == 'POST' and form.validate():
        name = current_user.username
        comment = form.comment.data

        comment = Page(name, comment, 'badshah')
        db.session.add(comment)
        db.session.commit()
        flash('Comments Added', 'success')
        return redirect('badshah')

    return render_template('badshah.html', form=form, page=Page.query.filter_by(pages='badshah'))


@app.route('/fort', methods=['GET', 'POST'])
@login_required
def fort():
    form = PageForm(request.form)
    if request.method == 'POST' and form.validate():
        name = current_user.username
        comment = form.comment.data

        comment = Page(name, comment, 'fort')
        db.session.add(comment)
        db.session.commit()
        flash('Comments Added', 'success')
        return redirect('fort')

    return render_template('fort.html', form=form, page=Page.query.filter_by(pages='fort'))


# _______________________________________________________________________________________

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
