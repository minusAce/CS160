from bson.objectid import ObjectId
from flask import Flask, render_template, redirect, url_for, request, jsonify
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from pymongo import MongoClient
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError

app = Flask(__name__)
app.config['SECRET_KEY'] = 'CS160Project'

bcrypt = Bcrypt(app)

# Connect to MongoDB
client = MongoClient("mongodb+srv://Rex:abcd123@cluster0.7xpphgj.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")
db = client["user_auth"]
users_collection = db["users"]
products_collection = db["products"]  # Added products collection

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User class
class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data['_id'])
        self.username = user_data['username']
        self.password = user_data['password']

    @staticmethod
    def get_by_username(username):
        user_data = users_collection.find_one({"username": username})
        if user_data:
            return User(user_data)
        return None

    @staticmethod
    def get_by_id(user_id):
        user_data = users_collection.find_one({"_id": ObjectId(user_id)})
        if user_data:
            return User(user_data)
        return None

@login_manager.user_loader
def load_user(user_id):
    return User.get_by_id(user_id)

# Forms
class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)],
                           render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)],
                             render_kw={"placeholder": "Password"})
    submit = SubmitField("Register")

    def validate_username(self, username):
        if users_collection.find_one({"username": username.data}):
            raise ValidationError("That username already exists. Please choose a different one.")

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)],
                           render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)],
                             render_kw={"placeholder": "Password"})
    submit = SubmitField("Login")

# Routes
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', name=current_user.username)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.get_by_username(form.username.data)
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        users_collection.insert_one({
            "username": form.username.data,
            "password": hashed_password
        })
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Products API endpoints
@app.route('/products', methods=['POST'])
@login_required
def add_product():
    data = request.get_json()

    new_product = {
        "title": data.get('title'),
        "price": data.get('price'),
        "image_url": data.get('imageUrl'),
        "description": data.get('description'),
        "materials_used": data.get('materialsUsed'),
        "ingredients": data.get('ingredients'),
        "origin": data.get('origin'),
        "certifications": data.get('certifications'),
        "packaging": data.get('packaging'),
        "earth_friendly_features": data.get('earthFriendlyFeatures'),
        "seller_message": data.get('sellerMessage'),
        "care_instructions": data.get('careInstructions')
    }

    products_collection.insert_one(new_product)
    return jsonify({'message': 'Product added successfully'}), 201

@app.route('/products', methods=['GET'])
def get_products():
    products = products_collection.find()
    product_list = []
    for product in products:
        product_data = {
            'id': str(product['_id']),
            'title': product.get('title'),
            'price': product.get('price'),
            'image_url': product.get('image_url'),
            'description': product.get('description'),
            'materials_used': product.get('materials_used'),
            'ingredients': product.get('ingredients'),
            'origin': product.get('origin'),
            'certifications': product.get('certifications'),
            'packaging': product.get('packaging'),
            'earth_friendly_features': product.get('earth_friendly_features'),
            'seller_message': product.get('seller_message'),
            'care_instructions': product.get('care_instructions')
        }
        product_list.append(product_data)
    return jsonify(product_list), 200

# Get a specific product by ID
@app.route('/products/<product_id>', methods=['GET'])
def get_product(product_id):
    try:
        product = products_collection.find_one({"_id": ObjectId(product_id)})
        if product:
            product_data = {
                'id': str(product['_id']),
                'title': product.get('title'),
                'price': product.get('price'),
                'image_url': product.get('image_url'),
                'description': product.get('description'),
                'materials_used': product.get('materials_used'),
                'ingredients': product.get('ingredients'),
                'origin': product.get('origin'),
                'certifications': product.get('certifications'),
                'packaging': product.get('packaging'),
                'earth_friendly_features': product.get('earth_friendly_features'),
                'seller_message': product.get('seller_message'),
                'care_instructions': product.get('care_instructions')
            }
            return jsonify(product_data), 200
        return jsonify({"message": "Product not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# Update a product
@app.route('/products/<product_id>', methods=['PUT'])
@login_required
def update_product(product_id):
    data = request.get_json()

    try:
        result = products_collection.update_one(
            {"_id": ObjectId(product_id)},
            {"$set": {
                "title": data.get('title'),
                "price": data.get('price'),
                "image_url": data.get('imageUrl'),
                "description": data.get('description'),
                "materials_used": data.get('materialsUsed'),
                "ingredients": data.get('ingredients'),
                "origin": data.get('origin'),
                "certifications": data.get('certifications'),
                "packaging": data.get('packaging'),
                "earth_friendly_features": data.get('earthFriendlyFeatures'),
                "seller_message": data.get('sellerMessage'),
                "care_instructions": data.get('careInstructions')
            }}
        )

        if result.modified_count > 0:
            return jsonify({"message": "Product updated successfully"}), 200
        return jsonify({"message": "Product not found or no changes made"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# Delete a product
@app.route('/products/<product_id>', methods=['DELETE'])
@login_required
def delete_product(product_id):
    try:
        result = products_collection.delete_one({"_id": ObjectId(product_id)})
        if result.deleted_count > 0:
            return jsonify({"message": "Product deleted successfully"}), 200
        return jsonify({"message": "Product not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# Run the app
if __name__ == '__main__':
    app.run(debug=True)
