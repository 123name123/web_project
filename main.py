from flask import Flask, render_template, redirect, request, session, flash
from data import db_session
from data import users, products
import os
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, SelectField, IntegerField
from wtforms.fields.html5 import EmailField
from wtforms.validators import DataRequired, NumberRange
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
# from flask_ngrok import run_with_ngrok
import datetime
from flask_restful import Api
import product_resource

app = Flask(__name__)
api = Api(app)
app.debug = True
# run_with_ngrok(app)

UPLOAD_FOLDER = f'{os.getcwd()}\\static\\img\\profile_img'

app.config['SECRET_KEY'] = '12345aA'
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(days=1)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

login_manager = LoginManager()
login_manager.init_app(app)


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() == 'jpg'


def get_profile_img():
    os.chdir('static\\img\\profile_img')
    if os.access(f'{current_user.id}.jpg', os.F_OK):
        filename = str(current_user.id)
    else:
        if current_user.gender[0] == 'М':
            filename = 'profilem'
        else:
            filename = 'profilef'
    os.chdir('..\\..\\..')
    return filename


def find_products(tag):
    sessions = db_session.create_session()
    all_products = sessions.query(products.Products).all()
    ans_products = list()
    for item in all_products:
        title = item.title.lower()
        if tag in title or title in tag or (len(tag) > 2 and tag[:-1] in title) or (
                len(tag) > 2 and tag[:-2] in title):
            ans_products.append(item)
    return ans_products


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
    if current_user.is_authenticated:
        filename = get_profile_img()
    else:
        filename = 'profilem'
    if request.method == 'POST':
        session['tag'] = request.form['search']
        return redirect('/')
    all_product = find_products(session.get('tag', '').lower())
    if session.get('reverse', False):
        sim = '▲'
    else:
        sim = '▼'
    simp = simc = simn = ''
    pos = session.get('sort', 'none')
    if pos == 'price':
        all_product.sort(key=lambda x: x.price, reverse=session.get('reverse', False))
        simp = sim
    elif pos == 'count':
        all_product.sort(key=lambda x: x.existence, reverse=session.get('reverse', False))
        simc = sim
    elif pos == 'name':
        simn = sim
        all_product.sort(key=lambda x: x.title, reverse=session.get('reverse', False))
    return render_template('index.html', basket_count=session.get('basket_count', 0),
                           title="CoolStore", tag=session.get('tag', ''),
                           filename=filename, product=all_product, simc=simc, simn=simn, simp=simp)


@app.route('/login', methods=['GET', 'POST'])
def login():
    session['tag'] = ''
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
    return render_template('login_form.html', basket_count=session.get('basket_count', 0),
                           title='Авторизация', form=form, filename="profilem")


@app.route('/logout')
@login_required
def logout():
    session['tag'] = ''
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
    submit = SubmitField('Подтвердить')


class LengthError(Exception):
    error = 'Пароль должен состоять не менее чем из 8 символов!'


class SymbolError(Exception):
    error = 'В пароле должна быть хотя бы один символ!'


class LetterError(Exception):
    error = 'В пароле должна быть хотя бы одна большая и маленькая буква!'


class DigitError(Exception):
    error = 'В пароле должна быть хотя бы одна цифра!'


def bool_ys(password):
    ys = [0, 0, 0, 0]
    for i in password:
        if i.isdigit():
            ys[0] = 1
        elif i.isalpha():
            if i.isupper():
                ys[1] = 1
            else:
                ys[2] = 1
        else:
            ys[3] = 1
    if ys[2] * ys[1] == 0:
        raise LetterError
    if ys[0] == 0:
        raise DigitError
    if ys[3] == 0:
        raise SymbolError
    return 'ok'


def check_password(password):
    try:
        if len(password) <= 8:
            raise LengthError
        bool_ys(password)
        return 'OK'
    except Exception as ex:
        return ex.error


@app.route('/register', methods=['GET', 'POST'])
def reqister():
    form = RegisterForm()
    if form.validate_on_submit():
        result = check_password(form.password.data)
        if result != 'OK':
            return render_template('reg.html', basket_count=session.get('basket_count', 0),
                                   title='Регистрация',
                                   form=form, email_error="OK", again_password_error="OK",
                                   password_error=result)
        if form.password.data != form.password_again.data:
            return render_template('reg.html', basket_count=session.get('basket_count', 0),
                                   title='Регистрация',
                                   form=form, email_error="OK", password_error="OK",
                                   again_password_error="Пароли не совпадают")
        db_session.global_init('db/blogs.sqlite')
        session_in_db = db_session.create_session()
        if session_in_db.query(users.User).filter(users.User.email == form.email.data).first():
            return render_template('reg.html', basket_count=session.get('basket_count', 0),
                                   title='Регистрация',
                                   form=form, password_error="OK", again_password_error="OK",
                                   email_error="Такой пользователь уже есть")
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
    return render_template('reg.html', basket_count=session.get('basket_count', 0),
                           title='Регистрация', form=form, filename="profilem",
                           email_error="OK", password_error="OK", again_password_error="OK")


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'GET':
        filename = get_profile_img()
        params = {
            'title': 'Профиль',
            'filename': filename,
            'id': current_user.id,
            'name': current_user.name,
            'sname': current_user.surname,
            'mname': current_user.midname,
            'gender': current_user.gender,
            'age': current_user.age,
            'basket_count': session.get('basket_count', 0)
        }
        return render_template('profile.html', **params)
    elif request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], f'{current_user.id}.jpg'))
            return redirect('/profile')


@app.route('/basket', methods=['GET', 'POST'])
@login_required
def basket():
    sessions = db_session.create_session()
    filename = get_profile_img()
    user = load_user(current_user.id)
    bask = [[int(x.split('-')[0]), int(x.split('-')[1])] for x in user.basket.strip().split()]
    bask = list(map(lambda x: [sessions.query(products.Products).get(x[0]), x[1]], bask))
    session['basket_count'] = len(bask)
    return render_template('basket.html', basket_count=session.get('basket_count', 0),
                           title='Корзина', filename=filename, bask=bask)


@app.route('/delete/<int:product_id>', methods=['GET', 'POST'])
def delete(product_id):
    sessions = db_session.create_session()
    user = sessions.query(users.User).get(current_user.id)
    bask = [[int(x.split('-')[0]), int(x.split('-')[1])] for x in user.basket.strip().split()]
    bask = list(filter(lambda x: x[0] != product_id, bask))
    bask = ' '.join(['-'.join([str(x[0]), str(x[1])]) for x in bask])
    bask += ' '
    user.basket = bask
    sessions.commit()
    return redirect('/basket')


@app.route('/redact_profile', methods=['GET', 'POST'])
@login_required
def redact_profile():
    db_session.global_init('db/blogs.sqlite')
    session_in_db = db_session.create_session()
    user = session_in_db.query(users.User).get(current_user.id)
    form = RegisterForm()
    if request.method == 'GET':
        if user.gender == 'Мужской':
            gen = '1'
        else:
            gen = '2'
        form.gender.data = gen
        form.name.data = user.name
        form.mname.data = user.midname
        form.age.data = user.age
        form.surname.data = user.surname
    elif request.method == 'POST':
        if form.gender.data == '1':
            gen = "Мужской"
        else:
            gen = "Женский"
        user.gender = gen
        user.name = form.name.data
        user.midname = form.mname.data
        user.age = form.age.data
        user.surname = form.surname.data
        session_in_db.commit()
        return redirect('/profile')
    filename = get_profile_img()
    return render_template('redact_profile.html', form=form, filename=filename,
                           title='Редактирование')


class Buy(FlaskForm):
    count = IntegerField('Колличество:', validators=[DataRequired(), NumberRange(1)],
                         default=1)
    submit = SubmitField('В корзину')


@app.route('/product/<int:product_id>', methods=['GET', 'POST'])
def product(product_id):
    form = Buy()
    if current_user.is_authenticated:
        filename = get_profile_img()
    else:
        filename = 'profilem'
    sessions = db_session.create_session()
    prod = sessions.query(products.Products).get(product_id)
    if form.validate_on_submit():
        if current_user.is_authenticated:
            if sessions.query(products.Products).get(product_id).existence:
                sessions = db_session.create_session()
                user = sessions.query(users.User).get(current_user.id)
                if user.basket:
                    bask = [[int(x.split('-')[0]), int(x.split('-')[1])] for x in
                            user.basket.strip().split()]
                    change = False
                    for item in bask:
                        if item[0] == product_id:
                            item[1] += form.count.data
                            change = True
                    if not change:
                        user.basket = user.basket + f'{product_id}-{form.count.data} '
                    else:
                        bask = ' '.join(['-'.join([str(x[0]), str(x[1])]) for x in bask])
                        bask += ' '
                        user.basket = bask
                else:
                    user.basket = f'{product_id}-{form.count.data} '
                sessions.commit()
            else:
                return render_template('product.html', prod=prod, filename=filename,
                                       title=prod.title,
                                       form=form, message='Товара нет в наличии!')
        else:
            return render_template('product.html', prod=prod, filename=filename,
                                   basket_count=session.get('basket_count', 0), title=prod.title,
                                   form=form, message='Вы не авторизованы')
        return redirect('/basket')
    return render_template('product.html', prod=prod, filename=filename,
                           basket_count=session.get('basket_count', 0), title=prod.title,
                           form=form)


@app.route('/redact_prod_plus/<int:product_id>', methods=['GET', 'POST'])
def redact_prod_plus(product_id):
    sessions = db_session.create_session()
    user = sessions.query(users.User).get(current_user.id)
    bask = [[int(x.split('-')[0]), int(x.split('-')[1])] for x in
            user.basket.strip().split()]
    for item in bask:
        if item[0] == product_id:
            item[1] += 1
    bask = ' '.join(['-'.join([str(x[0]), str(x[1])]) for x in bask])
    bask += ' '
    user.basket = bask
    sessions.commit()
    return redirect('/basket')


@app.route('/redact_prod_minus/<int:product_id>', methods=['GET', 'POST'])
def redact_prod_minus(product_id):
    sessions = db_session.create_session()
    user = sessions.query(users.User).get(current_user.id)
    bask = [[int(x.split('-')[0]), int(x.split('-')[1])] for x in
            user.basket.strip().split()]
    for item in bask:
        if item[0] == product_id:
            item[1] -= 1
    bask = list(filter(lambda x: x[1] > 0, bask))
    bask = ' '.join(['-'.join([str(x[0]), str(x[1])]) for x in bask])
    bask += ' '
    user.basket = bask
    sessions.commit()
    return redirect('/basket')


@app.route('/change/<string:pos>')
def change(pos):
    last_pos = session.get('sort', 'none')
    if last_pos == pos:
        session['reverse'] = not session.get('reverse', False)
    else:
        session['reverse'] = False
    session['sort'] = pos
    return redirect('/')


class ChangePasswordForm(FlaskForm):
    old_password = PasswordField('Старый пароль', validators=[DataRequired()])
    new_password = PasswordField('Новый пароль', validators=[DataRequired()])
    again_password = PasswordField('Повторите новый пароль', validators=[DataRequired()])
    submit = SubmitField('Сменить пароль')


@app.route('/change_password', methods=['GET', "POST"])
@login_required
def change_password():
    filename = get_profile_img()
    form = ChangePasswordForm()
    if form.validate_on_submit():
        db_session.global_init('db/blogs.sqlite')
        session_in_db = db_session.create_session()
        user = session_in_db.query(users.User).get(current_user.id)
        if user.hashed_password != form.old_password.data:
            return render_template('change_password.html',
                                   basket_count=session.get('basket_count', 0), title='Регистрация',
                                   form=form, old_password_error="Неверный пароль",
                                   again_password_error="OK", new_password_error="OK",
                                   filename=filename)
        result = check_password(form.new_password.data)
        if user.hashed_password == form.new_password.data:
            return render_template('change_password.html',
                                   basket_count=session.get('basket_count', 0), title='Регистрация',
                                   form=form, old_password_error="OK", again_password_error="OK",
                                   new_password_error="Новый пароль не должен совпадть со старым!",
                                   filename=filename)
        if result != 'OK':
            return render_template('change_password.html',
                                   basket_count=session.get('basket_count', 0), title='Регистрация',
                                   form=form, old_password_error="OK", again_password_error="OK",
                                   new_password_error=result, filename=filename)
        if form.new_password.data != form.again_password.data:
            return render_template('change_password.html',
                                   basket_count=session.get('basket_count', 0), title='Регистрация',
                                   form=form, old_password_error="OK", new_password_error="OK",
                                   again_password_error="Пароли не совпадают!", filename=filename)
        user.hashed_password = form.new_password.data
        session_in_db.commit()
        return redirect('/profile')
    return render_template('change_password.html', form=form,
                           basket_count=session.get('basket_count', 0), title="Сменить пароль",
                           filename=filename, old_password_error="OK", again_password_error="OK",
                           new_password_error="OK")


def main():
    db_session.global_init("db/blogs.sqlite")
    api.add_resource(product_resource.ProductListResource, '/api/v2/products')
    api.add_resource(product_resource.ProductResource, '/api/v2/products/<int:product_id>')
    app.run()


if __name__ == '__main__':
    main()
