from flask import Flask, render_template, redirect, url_for, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, DateField, IntegerField, TextAreaField, validators
from wtforms.validators import InputRequired, Email, EqualTo, Length
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import pymysql
import flask_admin as admin
from flask_admin import Admin, helpers, expose
from flask_admin.contrib.sqla import ModelView
from flask_admin.contrib import sqla

app = Flask(__name__)

app.config["SECRET_KEY"] = "thisisasecret"
app.config["SQLALCHEMY_DATABASE_URI"] = 'sqlite:///C:\\sqlite\\Attendant.db'
app.config["SQLALCHEMY_BINDS"] = {"two": "mysql+pymysql://root:philacher@localhost/attendance_book"}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app, pymysql)

login_manager = LoginManager()
login_manager.init_app(app)

class Code(UserMixin, db.Model):
    __tablename__ = "code"
    id = db.Column(db.Integer, primary_key = True)
    code = db.Column(db.String(10))

class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))

    def __init__(self,  username, email ,password):

        self.username = username
        self.email = email
        self.password = password

class Records(db.Model):
    __bind_key__ = 'two'
    __tablename__ = 'recordsbook'
    id = db.Column(db.Integer, primary_key=True)
    meeting_day = db.Column(db.String(15))
    date = db.Column(db.String(50))
    attendance = db.Column(db.String(80))
    comment = db.Column(db.String(1000))

    def __init__(self,  meeting_day, date, attendance, comment):
        self.meeting_day = meeting_day
        self.date = date
        self.attendance = attendance
        self.comment = comment

class admindb(db.Model):
    __tablename__  = 'admindb'
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(80), unique=True)
    password = db.Column(db.String(64))

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return self.id

    # Required for administrative interface
    def __unicode__(self):
        return self.username

class LoginForm(FlaskForm):
    login = StringField(validators=[validators.required()])
    password = PasswordField(validators=[validators.required()])


class MyModelView(sqla.ModelView):
    can_delete = False
    can_export = True

    def is_accessible(self):
        return current_user.is_authenticated


class MyAdminIndexView(admin.AdminIndexView):
    @expose('/')
    def index(self):
        if not current_user.is_authenticated:
            return redirect(url_for('.login_view'))
        return super(MyAdminIndexView, self).index()

    @expose('/login/', methods=('GET', 'POST'))
    def login_view(self):
        # handle user login
        form = LoginForm()

        if form.validate_on_submit():
            user = admindb.query.filter_by(login=form.login.data).first()

            print (user)
            if not user:
                flash('Administrator not found !')
            if user:
                if not check_password_hash(user.password, form.password.data):
                    flash('Wrong Password typed!')
                if check_password_hash(user.password, form.password.data):
                    login_user(user)
                    return redirect(url_for('.index'))
        link = '<h2><em>Only Administrators are Allow..!</em></h2>'
        self._template_args['form'] = form
        self._template_args['link'] = link
        return super(MyAdminIndexView, self).index()

    @expose('/logout/')
    def logout_view(self):
        logout_user()
        flash('You have successfully logged out')
        return redirect(url_for('.index'))

# admin init
admin = Admin(app, 'Views: Admin', index_view=MyAdminIndexView(), base_template='admin_view.html')

# flask - admin views
admin.add_view(MyModelView(Records, db.session))



   # Form classes for wtf
class checkform(FlaskForm):
    code = PasswordField(" ", validators=[InputRequired("Enter Attendant code")])

class signupform(FlaskForm):
    username = StringField("Username", validators=[InputRequired("Username required"), Length(min=4 ,max=10,message="username should between 5 to 8 characters")])
    email = StringField("Email", validators=[InputRequired(message="Enter your email"), Email(message="an Invalid Email account name!")])
    password = PasswordField("Password", validators=[InputRequired(message="Enter your password"), Length(min=5, max=10,message="password is not strong!")])
    confirm = PasswordField("Confirm Password", validators=[InputRequired("confirm your password"),EqualTo("password",message="Your password did not match!")])

class loginform(FlaskForm):
    username = StringField("Username", validators=[InputRequired("Enter Username")])
    password = PasswordField("Password", validators=[InputRequired("Enter Password")])

class recordform(FlaskForm):
    format = "YY-MM-DD"
    day = StringField("Meeting Day", validators=[InputRequired("Input required")])
    date = DateField("Date", validators=[InputRequired("Input required")], format="%Y-%m-%d")
    attendance = IntegerField("Number of Attendance", validators=[InputRequired("Input required")])
    comment = TextAreaField("Comments")


@login_manager.user_loader
def user_loader(user_id):
    return User.query.get(int(user_id))


#  Routes
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/codecheck", methods=["GET","POST"])
def codecheck():
    form = checkform()

    if form.validate_on_submit():
        code = Code.query.filter_by(code=form.code.data).first()
        print (code)
        if not code:
            flash('Invalid code !')
        if code:
            login_user(code)
            return redirect(url_for("signup"))
    return render_template("check.html", form=form)


@app.route("/signup", methods=["GET","POST"])
@login_required
def signup():
    form = signupform()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is not None:
            flash('Username already exists.')
            return redirect(url_for('signup'))
        mail = User.query.filter_by(email=form.email.data).first()
        if mail is not None:
            flash(' email already exists.')
            return redirect(url_for('signup'))
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(form.username.data, form.email.data, hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for("login"))

    return render_template("signup.html", form = form)


@app.route("/login", methods=["GET","POST"])
def login():
    form =loginform()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        print (user)
        if not user:
            flash('Username not found !')
        if user:
            if not check_password_hash(user.password, form.password.data):
                flash('Wrong Password typed!')
            if check_password_hash(user.password, form.password.data):
                login_user(user)
                flash('Hello %s !....You have Successfully logged in' %current_user.username)
                return redirect(url_for('main'))

    return render_template("login.html", form=form)



@app.route("/main", methods=["GET","POST"])
@login_required
def main():
    form = recordform()

    if form.validate_on_submit():
        new_user = Records(form.day.data, form.date.data, form.attendance.data, form.comment.data)
        db.session.add(new_user)
        db.session.commit()
        flash('Data Has been Submitted Successfully..!')
        return redirect(url_for("main"))
    name = current_user.username.upper()
    return render_template("main.html", form=form, name = name )

@app.route("/logout")
@login_required
def logout():
    flash("You have sucessfully Logged out!")
    logout_user()
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(debug=True)