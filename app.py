from flask import Flask, render_template, url_for, redirect
from flask_sqlalchemy import SQLAlchemy # sqlite
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db' # connects app file to database
app.config['SECRET_KEY'] = 'secretkey' # for session cookies
db = SQLAlchemy(app) # creates database instance

bcrypt = Bcrypt(app)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    __tablename__ = 'Users'
    user_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

    def get_id(self):
        return str(self.user_id)

class TaskType(db.Model):
    __tablename__ = 'TaskTypes'
    type_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    priority_level = db.Column(db.Integer)
    category = db.Column(db.String(50), nullable=False)
    description = (db.String(300))

class Task(db.Model):
    __tablename__ = 'Tasks'
    task_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    task_name = db.Column(db.String(100), nullable=False)
    type_id = db.Column(db.Integer, db.ForeignKey('TaskTypes.type_id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('Users.user_id'), nullable=False)

class TimeLog(db.Model):
    __tablename__ = 'TimeLogs'
    log_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    task_id = db.Column(db.Integer, db.ForeignKey('Tasks.task_id'), nullable=False)
    estimate_time = db.Column(db.Integer, nullable=False)
    actual_time = db.Column(db.Integer, nullable=False)
    date_logged = db.Column(db.String(50), nullable=False)

class RegisterForm(FlaskForm):
    first_name = StringField(
        validators=[InputRequired(), Length(min=2, max=50)],
        render_kw={"placeholder": "First Name"})
    
    last_name = StringField(
        validators=[InputRequired(), Length(min=2, max=50)],
        render_kw={"placeholder": "Last Name"})
    
    email = StringField(
        validators=[InputRequired(), Length(min=4, max=100)],
        render_kw={"placeholder": "Email"})
    
    password = PasswordField(
        validators=[InputRequired(), Length(min=4, max=20)],
        render_kw={"placeholder": "Password"})
    
    submit = SubmitField("Register")

    def validate_email(self, email):
        existing_user_email = User.query.filter_by(email=email.data).first()
        
        if existing_user_email:
            raise ValidationError("That email is already in use. Please choose a different one.")


class LoginForm(FlaskForm):    
    email = StringField(
        validators=[InputRequired(), Length(min=4, max=100)],
        render_kw={"placeholder": "Email"})
    
    password = PasswordField(
        validators=[InputRequired(), Length(min=4, max=20)],
        render_kw={"placeholder": "Password"})
    
    submit = SubmitField("Login")

    

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login',methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
        logout_user()
        return redirect(url_for('login'))

@app.route('/register', methods=['GET','POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(
            first_name=form.first_name.data, 
            last_name=form.last_name.data, 
            email=form.email.data, 
            password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)


if __name__ == '__main__':
    app.run(debug=True)