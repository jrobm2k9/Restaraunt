from flask import Flask, render_template, redirect, request
from flask.helpers import url_for
from flask_login.utils import login_required
from flask_wtf import FlaskForm
from flask_wtf.recaptcha import validators
from wtforms import StringField, PasswordField, BooleanField, SubmitField, SelectField
from wtforms.validators import DataRequired, ValidationError, DataRequired, Email, EqualTo
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import os
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, current_user, login_user, logout_user
from werkzeug.urls import url_parse

basedir = os.path.abspath(os.path.dirname('app.py'))
app = Flask(__name__)
app.config['SECRET_KEY'] = 'cs3320'

# db configuration according to the website
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or 'sqlite:///' + os.path.join(basedir, 'app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db)
loggin = LoginManager(app)
loggin.login_view = 'login'

# login class to handle the form
class Login(FlaskForm):
    user = StringField('User', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Sign In')

# menu class for the menu form
class Food_Menu(FlaskForm):
    # food_menu = SelectField('MenuType', choices=[("Breakfast", "breakfast"), ("Lunch", "lunch"), ("Dinner", "dinner")])
    breakfast_menu = SelectField('Breakfast', choices=["3 Carne Guisada $5.99", "3 Carne Guisada with Beans $5.99", "3 Carne Guisada with Eggs $6.99", "3 Potato and Bean $3.99", "3 Potato and Bean with Bacon $5.99", "3 Potato and Bean with Eggs $5.99", "3 Picadillo with Cheese $7.99", "3 Picadillo with Beans $8.99", "3 Picadillo with Eggs $9.99"])
    total = SelectField('Quantity', choices=[x for x in range(100)], default=[1])
    submit = SubmitField("Checkout")

# user database model
class Users(UserMixin,db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user = db.Column(db.String(40), index=True, unique=True)
    # email = db.Column(db.String(40), index=True, unique=True)
    hashed_password = db.Column(db.String(128))
    user_cart = db.relationship('Cart', backref='author', lazy='dynamic')

    def set_password(self, password):
        self.hashed_password = generate_password_hash(password)

    def password_check(self, password):
        return check_password_hash(self.hashed_password, password)

    def __repr__(self) -> str:
        return 'Users {}'.format(self.user)

# user cart db model
class Cart(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    menu_item = db.Column(db.String(120), index=True)
    item_count = db.Column(db.Integer)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    def __repr__(self) -> str:
        return 'Cart {}'.format(self.menu_item)


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/menu', methods=['GET', 'POST'])
def menu():
    form = Food_Menu()
    if form.validate_on_submit():
        print("item: ", type(form.breakfast_menu.data))
        print("total: ", type(form.total.data))
        cart = Cart(menu_item=form.breakfast_menu.data, item_count=form.total.data)
        db.session.add(cart)
        db.session.commit()
        return redirect(url_for('checkout'))
    return render_template('menu.html', form=form)

@app.route('/menu/about')
def about():
    return render_template('about.html')

@app.route('/menu/contact')
def contact():
    return render_template('contact.html')


# attempts to login the user, if the user is not in the db, it creates a new user
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = Login()
    if form.validate_on_submit():
        username = Users.query.filter_by(user=form.user.data).first()
        print("This is username: ", form.user.data)
        # if username is None or not username.check_password(form.password.data):
            # return redirect(url_for('login'))
        if  username is None and form.password.data is not None:
            print("This is a new user ")
            newuser = Users(user=form.user.data)
            newuser.set_password(form.password.data)
            db.session.add(newuser)
            db.session.commit()
            return redirect(url_for('login'))
        else:
            login_user(username, remember=form.remember.data)
            next_page = request.args.get('next')
            if not next_page or url_parse(next_page).netloc != '':
                next_page = url_for('checkout')
        return redirect(url_for('checkout'))
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


# for flask shell session
@app.shell_context_processor
def shell_context():
    return {'db': db, 'Users': Users, 'Cart': Cart}

@loggin.user_loader
def load_user(id):
    return Users.query.get(int(id))

@app.route('/checkout')
@login_required
def checkout():
    return render_template('checkout.html', cart=Cart.query.all())