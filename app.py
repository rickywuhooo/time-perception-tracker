from flask import Flask, render_template, url_for, redirect, request
from flask_sqlalchemy import SQLAlchemy # sqlite
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, IntegerField, DateField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from datetime import datetime
from flask_migrate import Migrate

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db' # connects app file to database
app.config['SECRET_KEY'] = 'secretkey' # for session cookies
db = SQLAlchemy(app) # creates database instance

bcrypt = Bcrypt(app)

migrate = Migrate(app, db)


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
    description = db.Column(db.String(300))

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


class TaskTypeForm(FlaskForm):
    category = StringField(
        "Category",
        validators=[InputRequired(), Length(max=50)])
    priority_level = SelectField(
        "Priority Level",
        choices = [(1, "Low"), (2, "Medium"), (3, "High")],
        coerce = int,
        validators = [InputRequired()])
    description = StringField(
        "Description (optional)",
        validators = [Length(max=300)])
    submit = SubmitField("Add Task Category")

class TaskForm(FlaskForm):
    task_name = StringField(
        "Task Name", 
        validators=[InputRequired()])
    category = SelectField(
        "Category",
        coerce=int) # string to int
    estimate_time = IntegerField(
        "Estimated Time (minutes)",
        validators=[InputRequired()])
    actual_time = IntegerField(
        "Actual Time (minutes)",
        validators=[InputRequired()])
    submit = SubmitField("Submit")

class UpdateTaskTypeForm(FlaskForm):
    category = StringField(
        "Category",
        validators=[InputRequired(), Length(max=50)])
    priority_level = SelectField(
        "Priority Level",
        choices=[(1, "Low"), (2, "Medium"), (3, "High")],
        coerce=int,
        validators=[InputRequired()])
    description = StringField(
        "Description (optional)",
        validators=[Length(max=300)])
    submit = SubmitField("Update Category")

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

    # adding tasks
    task_form = TaskForm()
    task_form.category.choices = [(t.type_id, t.category) for t in TaskType.query.all()]
    
    if task_form.validate_on_submit() and 'add_task' in request.form:
        new_task = Task(
            task_name = task_form.task_name.data,
            type_id = task_form.category.data,
            user_id = current_user.user_id)
        db.session.add(new_task)
        db.session.commit()

        new_log = TimeLog(
            task_id = new_task.task_id,
            estimate_time = task_form.estimate_time.data,
            actual_time = task_form.actual_time.data,
            date_logged = datetime.now().strftime("%Y-%m-%d"))
        db.session.add(new_log)
        db.session.commit()
        return redirect(url_for('dashboard'))

    # adding task categories
    tasktype_form = TaskTypeForm()
    if tasktype_form.validate_on_submit() and 'add_task_type' in request.form:
        new_type = TaskType(
            category = tasktype_form.category.data,
            priority_level = tasktype_form.priority_level.data,
            description = tasktype_form.description.data)
        db.session.add(new_type)
        db.session.commit()
        return redirect(url_for('dashboard'))


    user_tasks = Task.query.filter_by(user_id=current_user.user_id).all()
    task_info = []
    for task in user_tasks:
        log = TimeLog.query.filter_by(task_id=task.task_id).first()
        category = TaskType.query.get(task.type_id)
        task_info.append({
            "task_id": task.task_id,
            "task name": task.task_name,
            "category": category.category,
            "priority": category.priority_level,
            "estimated": log.estimate_time,
            "actual": log.actual_time,
            "date created": log.date_logged})

    categories = TaskType.query.all()

    return render_template(
        'dashboard.html', 
        task_form=task_form, 
        tasktype_form=tasktype_form, 
        task_info=task_info, 
        categories=categories)

@app.route('/delete_task/<int:task_id>', methods=['POST'])
@login_required
def delete_task(task_id):
    task = Task.query.get_or_404(task_id)
    
    # checking the task belongs to the current user
    if task.user_id != current_user.user_id:
        return redirect(url_for('dashboard'))

    # need to delete the associated TimeLog first
    log = TimeLog.query.filter_by(task_id=task_id).first()
    if log:
        db.session.delete(log)

    # delete the task
    db.session.delete(task)
    db.session.commit()
    
    return redirect(url_for('dashboard'))

@app.route('/delete_category/<int:type_id>', methods=['POST'])
@login_required
def delete_category(type_id):
    category = TaskType.query.get_or_404(type_id)

    tasks = Task.query.filter_by(type_id=type_id, user_id=current_user.user_id).all()

    for task in tasks:
        # need to delete the associated TimeLog first
        log = TimeLog.query.filter_by(task_id=task.task_id).first()
        if log:
            db.session.delete(log)
        db.session.delete(task)

    # delete the category
    db.session.delete(category)
    db.session.commit()

    return redirect(url_for('dashboard'))

@app.route('/update_task/<int:task_id>', methods=['GET', 'POST'])
@login_required
def update_task(task_id):
    task = Task.query.get_or_404(task_id)
    
    if task.user_id != current_user.user_id:
        return redirect(url_for('dashboard'))

    task_form = TaskForm()
    task_form.category.choices = [(t.type_id, t.category) for t in TaskType.query.all()]
    
    if request.method == 'GET':
        task_form.task_name.data = task.task_name
        task_form.category.data = task.type_id
        log = TimeLog.query.filter_by(task_id=task_id).first()
        if log:
            task_form.estimate_time.data = log.estimate_time
            task_form.actual_time.data = log.actual_time
    
   
    if task_form.validate_on_submit():
        # update task details
        task.task_name = task_form.task_name.data
        task.type_id = task_form.category.data
        
        # update time log details
        log = TimeLog.query.filter_by(task_id=task_id).first()
        if log:
            log.estimate_time = task_form.estimate_time.data
            log.actual_time = task_form.actual_time.data
            log.date_logged = datetime.now().strftime("%Y-%m-%d")
        
        db.session.commit()
        return redirect(url_for('dashboard'))
    
    return render_template('update_task.html', task_form=task_form, task=task)

@app.route('/update_category/<int:type_id>', methods=['GET', 'POST'])
@login_required
def update_category(type_id):
    category = TaskType.query.get_or_404(type_id)
    
    tasks = Task.query.filter_by(type_id=type_id, user_id=current_user.user_id).all()
    if not tasks:
        return redirect(url_for('dashboard'))  # redirect if no tasks are associated with this category

    form = UpdateTaskTypeForm(obj=category)
    
    if form.validate_on_submit():
        category.category = form.category.data
        category.priority_level = form.priority_level.data
        category.description = form.description.data
        db.session.commit()
        return redirect(url_for('dashboard'))

    return render_template('update_category.html', form=form, category=category)

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