from flask import Flask,render_template,url_for,redirect
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_login import UserMixin,login_user,LoginManager,login_required,logout_user
from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField,SubmitField
from flask_bcrypt import Bcrypt
from wtforms.validators import InputRequired,Length,ValidationError

app=Flask(__name__,template_folder='templates')

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db= SQLAlchemy(app)
bcrypt=Bcrypt(app)

app.config['SECRET_KEY'] = 'secretkey'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model,UserMixin):
    id=db.Column(db.Integer,primary_key=True)
    username=db.Column(db.String(20),nullable=False,unique=True)
    password=db.Column(db.String(20),nullable=False)
    
class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(),Length(min=4,max=20)],render_kw={"placeholder":"username"})
    password = PasswordField (validators=[InputRequired(),Length(min=4,max=20)],render_kw={"placeholder":"username"})
    submit = SubmitField('register')
    
    def validate_username(self,username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError('the username already exists please choose a different name')
        
        
class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(),Length(min=4,max=20)],render_kw={"placeholder":"username"})
    password = PasswordField (validators=[InputRequired(),Length(min=4,max=20)],render_kw={"placeholder":"username"})
    submit = SubmitField('login')
    
    
@app.route("/")
def home():
    return render_template("home.html")


@app.route('/login',methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password,form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
    return render_template('login.html',form=form)
        

@app.route('/dashboard',methods=['GET','POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/logout',methods=['GET','POST'])
def logout():
    logout_user
    return redirect(url_for('login'))

@app.route('/register',methods=['GET','POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password = hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html',form=form)
class Todo(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    content=db.Column(db.String(200),nullable=False)
    completed=db.Column(db.Integer,default=0)
    date_created=db.Column(db.DateTime,default=datetime.utcnow)
    
def __repr__(self):
    return '<Task %r >' % self.id

@app.route('/',methods=['POST','GET'])
def index():
    if request.method =='POST':
        task_content = request.form['content']
        new_task = Todo(content=task_content)
        
        try:
            db.session.add(new_task)
            db.session.commit()
            return redirect('/')
        
        except:
            return 'There is an issue in adding the task'
    else:
            tasks = Todo.query.order_by(Todo.date_created).all()
            return render_template("index.html",tasks=tasks)
        
@app.route('/delete/<int:id>')
def delete(id):
  task_to_delete = Todo.query.get_or_404(id)
  
  try:
    db.session.delete(task_to_delete)
    db.session.commit()
    return redirect('/')
  except:
    return 'There was an issue in deleting the task'

@app.route('/update/<int:id>',methods=['GET','POST'])
def update(id):
  task_to_update = Todo.query.get_or_404(id)
  if request.method == 'POST':
    task_to_update.content = request.form['content']
    try:
      db.session.commit()
      return redirect('/')
    except:
      return 'There was an issue in updating the task'
  else:
    return render_template('update.html',task = task_to_update)


if __name__ == "__main__":
    app.run(debug=True)


