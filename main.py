from flask import Flask, render_template, redirect, request, jsonify, make_response, session
from data import db_session
from data import users
import os
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, SelectField
from wtforms.fields.html5 import EmailField
from wtforms.validators import DataRequired
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_ngrok import run_with_ngrok
import datetime

app = Flask(__name__)
run_with_ngrok(app)
app.config['SECRET_KEY'] = '12345aA'
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(days=1)

login_manager = LoginManager()
login_manager.init_app(app)


@app.errorhandler(404)
def not_found(error):
    return render_template('404.html')


@login_manager.user_loader
def load_user(user_id):
    db_session.global_init('db/blogs.sqlite')
    session_in_db = db_session.create_session()
    return session_in_db.query(users.User).get(user_id)


class LoginForm(FlaskForm):
    email = EmailField('Почта', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    remember_me = BooleanField('Запомнить меня')
    submit = SubmitField('Войти')


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        session['tag'] = request.form['search']
        return redirect('/')
    return render_template('index.html', title="CoolStore", tag=session.get('tag', ''))


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        db_session.global_init('db/blogs.sqlite')
        session_in_db = db_session.create_session()
        user = session_in_db.query(users.User).filter(users.User.email == form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember_me.data)
            return redirect("/")
        return render_template('login_form.html',
                               message="Неправильный логин или пароль",
                               form=form)
    return render_template('login_form.html', title='Авторизация', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect("/")


class RegisterForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    password_again = PasswordField('Повторите пароль', validators=[DataRequired()])
    surname = StringField('Фамилия', validators=[DataRequired()])
    name = StringField('Имя', validators=[DataRequired()])
    mname = StringField('Отчество(при наличии)', validators=[DataRequired()])
    gender = SelectField("Пол", validators=[DataRequired()], choices=[('1', 'М'), ('2', "Ж")])
    age = StringField('Возраст', validators=[DataRequired()])
    submit = SubmitField('Войти')


@app.route('/register', methods=['GET', 'POST'])
def reqister():
    form = RegisterForm()
    if form.validate_on_submit():
        if form.password.data != form.password_again.data:
            return render_template('reg.html', title='Регистрация',
                                   form=form,
                                   message="Пароли не совпадают")
        db_session.global_init('db/blogs.sqlite')
        session_in_db = db_session.create_session()
        if session_in_db.query(users.User).filter(users.User.email == form.email.data).first():
            return render_template('reg.html', title='Регистрация',
                                   form=form,
                                   message="Такой пользователь уже есть")
        if form.gender.data == '1':
            gen = "Мужской"
        else:
            gen = "Женский"
        user = users.User(
            name=form.name.data,
            midname=form.mname.data,
            gender=gen,
            email=form.email.data,
            surname=form.surname.data,
            age=form.age.data,
            hashed_password=form.password.data
        )
        session_in_db.add(user)
        session_in_db.commit()
        return redirect('/login')
    return render_template('reg.html', title='Регистрация', form=form)


@app.route('/profile')
@login_required
def profile():
    db_session.global_init('db/blogs.sqlite')
    session_in_db = db_session.create_session()
    user = session_in_db.query(users.User).get(current_user.id)
    os.chdir('static\\img\\profile_img')
    if os.access(f'{user.id}.jpg', os.F_OK):
        filename = f'{user.id}.jpg'
    else:
        if user.gender[0] == 'М':
            filename = 'profilem'
        else:
            filename = 'profilef'
    os.chdir('..\\..\\..')
    params = {
        'title': 'Профиль',
        'filename': filename,
        'id': user.id,
        'name': user.name,
        'sname': user.surname,
        'mname': user.midname,
        'gender': user.gender,
        'age': user.age
    }
    return render_template('profile.html', **params)


def main():
    app.run()


if __name__ == '__main__':
    main()
