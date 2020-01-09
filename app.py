from flask import Flask, render_template, redirect, url_for, request, flash
from flask import request
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy  import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_admin import Admin, AdminIndexView
from flask_admin.contrib.sqla import ModelView
from flask_mail import Mail, Message

app = Flask(__name__)
app.config['SECRET_KEY'] = 'Thisissupposedtobesecret!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['DEBUG'] = True
app.config['TESTING'] = False
app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_TSL'] = False
app.config['MAIL_USE_SSL'] = True
#app.config['MAIL_DEBUG'] = True
app.config['MAIL_USERNAME'] = 'adiphisake7@gmail.com'
app.config['MAIL_PASSWORD'] = 'nincompoop'
app.config['MAIL_DEFAULT_SENDER'] = 'adiphisake7@gmail.com'
app.config['MAIL_MAX_EMAILS'] = None
#app.config['MAIL_SUPPRESS_SEND'] = False
app.config['MAIL_ASCII_ATTACHMENTS'] = False

mail = Mail(app)

bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')

class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('dashboard'))

        return '<h1>Invalid username or password</h1>'
        #return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'

    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return '<h1>New user has been created!</h1>'
        #return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'

    return render_template('signup.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', name=current_user.username)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


class MyModelView(ModelView):
    def is_accessible(self):
        if current_user.id == 1 or current_user.id == 2:
            return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        flash('You Are Not an Admin!')
        return redirect(url_for('dashboard'))

class MyAdminIndexView(AdminIndexView):
    def is_accessible(self):
        if current_user.id == 1 or current_user.id == 2:
            return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        flash('You Are Not an Admin!')
        return redirect(url_for('dashboard'))

admin = Admin(app, index_view = MyAdminIndexView())
admin.add_view(MyModelView(User, db.session))

# @app.route('/admin')
# def admin_index():
#     return render_template('admin/index.html')

# @app.route('/admin', methods=['POST', 'GET'])
# def result():
#    if request.method == 'POST':
#       result = request.form
#       print('INSIDE')
#       return render_template('result.html',result = result)

message_str = " "

@app.route('/index', methods=['POST', 'GET'])
def fun():
    if request.method == 'POST':
        message_str = request.form['message']
    persons = User.query.all()
    for person in persons:
        msg = Message(message_str, recipients=[person.email])
        #mail.send(msg)
        print(message_str)
    flash('Mail Sent!')
    return redirect(url_for('admin.index'))

# @app.route('/emails')
# def emails():
#     persons = User.query.all()
#     for person in persons:
#         msg = Message(message_str, recipients=[person.email])
#         mail.send(msg)
#     # return render_template('emails.html', myPersons = persons)
#     return 'Message Sent'


if __name__ == '__main__':
    app.run(debug=True)
