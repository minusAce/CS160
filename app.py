from bson.objectid import ObjectId
from flask import Flask, render_template, redirect, url_for, request, jsonify, flash
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from flask_wtf.file import FileField
from werkzeug.utils import secure_filename
from pymongo import MongoClient
from wtforms import StringField, PasswordField, SubmitField, FloatField, TextAreaField
from wtforms.validators import InputRequired, Length, ValidationError, Optional, NumberRange
from datetime import datetime
import os
import uuid

app = Flask(__name__)
app.config['SECRET_KEY'] = 'CS160Project'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

# Create upload folder if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

bcrypt = Bcrypt(app)

# Connect to MongoDB
client = MongoClient(
    "mongodb+srv://Rex:abcd123@cluster0.7xpphgj.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")
db = client["user_auth"]
users_collection = db["users"]
products_collection = db["products"]  # Added products collection
messages_collection = db["messages"]


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
            raise ValidationError(
                "That username already exists. Please choose a different one.")


class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)],
                           render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)],
                             render_kw={"placeholder": "Password"})
    submit = SubmitField("Login")


class ProductForm(FlaskForm):
    title = StringField('Product Title', validators=[
                        InputRequired(), Length(max=120)])
    price = FloatField('Price', validators=[
                       InputRequired(), NumberRange(min=0)])
    image = FileField('Product Image', validators=[Optional()])
    imageUrl = StringField('Image URL', validators=[
                           Optional(), Length(max=255)])
    description = TextAreaField('Description', validators=[Optional()])
    materialsUsed = StringField('Materials Used', validators=[
                                Optional(), Length(max=255)])
    ingredients = StringField('Ingredients', validators=[
                              Optional(), Length(max=255)])
    origin = StringField('Origin', validators=[Optional(), Length(max=120)])
    certifications = StringField('Certifications', validators=[
                                 Optional(), Length(max=255)])
    packaging = StringField('Packaging', validators=[
                            Optional(), Length(max=255)])
    earthFriendlyFeatures = StringField(
        'Earth-Friendly Features', validators=[Optional(), Length(max=255)])
    sellerMessage = TextAreaField('Seller Message', validators=[Optional()])
    careInstructions = TextAreaField(
        'Care Instructions', validators=[Optional()])
    submit = SubmitField('Add Product')


def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


def save_image(file):
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        # Generate a unique filename to prevent collisions
        unique_filename = f"{uuid.uuid4()}_{filename}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(file_path)
        # Return the path relative to static folder for use in templates
        return f"/uploads/{unique_filename}"
    return None


# Routes
@app.route('/')
def home():
    return render_template('home.html')


@app.route('/dashboard')
@login_required
def dashboard():
    products = list(products_collection.find())
    for product in products:
        product['id'] = str(product['_id'])

    messages = list(messages_collection.find().sort('timestamp', -1).limit(10))
    return render_template('dashboard.html', name=current_user.username, products=products, messages=messages)


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
        hashed_password = bcrypt.generate_password_hash(
            form.password.data).decode('utf-8')
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


# Product form routes
@app.route('/productForm', methods=['GET', 'POST'])
@login_required
def add_product_form():
    form = ProductForm()

    if form.validate_on_submit():
        # Handle image upload
        image_path = None
        if form.image.data:
            image_path = save_image(form.image.data)

        # Use the image URL from the form if no file was uploaded
        image_url = image_path if image_path else form.imageUrl.data

        # Create product document
        new_product = {
            "title": form.title.data,
            "price": form.price.data,
            "image_url": image_url,
            "description": form.description.data,
            "materials_used": form.materialsUsed.data,
            "ingredients": form.ingredients.data,
            "origin": form.origin.data,
            "certifications": form.certifications.data,
            "packaging": form.packaging.data,
            "earth_friendly_features": form.earthFriendlyFeatures.data,
            "seller_message": form.sellerMessage.data,
            "care_instructions": form.careInstructions.data,
            "user_id": current_user.id  # Associate product with user
        }

        # Insert into MongoDB
        products_collection.insert_one(new_product)
        flash('Product added successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('add_product.html', form=form)


@app.route('/products/<product_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_product(product_id):
    # Fetch the product from MongoDB
    product = products_collection.find_one({"_id": ObjectId(product_id)})

    if not product:
        flash('Product not found', 'danger')
        return redirect(url_for('dashboard'))

    # Check if the current user owns this product (optional security check)
    if 'user_id' in product and product['user_id'] != current_user.id:
        flash('You do not have permission to edit this product', 'danger')
        return redirect(url_for('dashboard'))

    form = ProductForm()

    if request.method == 'GET':
        # Populate form with existing data
        form.title.data = product.get('title', '')
        form.price.data = product.get('price', 0)
        form.imageUrl.data = product.get('image_url', '')
        form.description.data = product.get('description', '')
        form.materialsUsed.data = product.get('materials_used', '')
        form.ingredients.data = product.get('ingredients', '')
        form.origin.data = product.get('origin', '')
        form.certifications.data = product.get('certifications', '')
        form.packaging.data = product.get('packaging', '')
        form.earthFriendlyFeatures.data = product.get(
            'earth_friendly_features', '')
        form.sellerMessage.data = product.get('seller_message', '')
        form.careInstructions.data = product.get('care_instructions', '')

    if form.validate_on_submit():
        # Handle image upload
        image_path = None
        if form.image.data:
            image_path = save_image(form.image.data)

        # Use the new image if uploaded, otherwise keep existing or use URL
        image_url = image_path if image_path else form.imageUrl.data
        if not image_url and 'image_url' in product:
            image_url = product['image_url']

        # Update product document
        products_collection.update_one(
            {"_id": ObjectId(product_id)},
            {"$set": {
                "title": form.title.data,
                "price": form.price.data,
                "image_url": image_url,
                "description": form.description.data,
                "materials_used": form.materialsUsed.data,
                "ingredients": form.ingredients.data,
                "origin": form.origin.data,
                "certifications": form.certifications.data,
                "packaging": form.packaging.data,
                "earth_friendly_features": form.earthFriendlyFeatures.data,
                "seller_message": form.sellerMessage.data,
                "care_instructions": form.careInstructions.data
            }}
        )

        flash('Product updated successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('edit_product.html', form=form, product=product)


# Products API endpoints
@app.route('/products', methods=['POST'])
@login_required
def add_product():
    data = request.get_json()

    # Associate product with the current user
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
        "care_instructions": data.get('careInstructions'),
        "user_id": current_user.id
    }

    result = products_collection.insert_one(new_product)
    return jsonify({
        'message': 'Product added successfully',
        'id': str(result.inserted_id)
    }), 201


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
        # Check if the product belongs to the current user
        product = products_collection.find_one({"_id": ObjectId(product_id)})
        if product and 'user_id' in product and product['user_id'] != current_user.id:
            return jsonify({"message": "You don't have permission to update this product"}), 403

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
        elif result.matched_count > 0:
            return jsonify({"message": "No changes made to the product"}), 200
        return jsonify({"message": "Product not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route('/products/<product_id>', methods=['POST', 'DELETE'])
@login_required
def delete_product(product_id):
    if request.method == 'POST':
        method_override = request.form.get('_method')
        if method_override and method_override.upper() == 'DELETE':
            try:
                # Check if the product belongs to the current user
                product = products_collection.find_one(
                    {"_id": ObjectId(product_id)})
                if product and 'user_id' in product and product['user_id'] != current_user.id:
                    return jsonify({"message": "You don't have permission to delete this product"}), 403

                result = products_collection.delete_one(
                    {"_id": ObjectId(product_id)})
                if result.deleted_count > 0:
                    flash('Product updated successfully!', 'success')
                    return redirect(url_for('dashboard'))
                return jsonify({"message": "Product not found"}), 404
            except Exception as e:
                return jsonify({"error": str(e)}), 400
        return None
    return None


@app.route('/chat')
@login_required
def user_list():
    users = list(users_collection.find(
        {"username": {"$ne": current_user.username}}))
    return render_template('users.html', users=users)


@app.route('/chat/<receiver>', methods=['GET', 'POST'])
@login_required
def chat(receiver):
    if request.method == 'POST':
        content = request.form.get('content')
        if content:
            messages_collection.insert_one({
                'sender': current_user.username,
                'receiver': receiver,
                'content': content,
                'timestamp': datetime.utcnow()
            })

    messages = list(messages_collection.find({
        '$or': [
            {'sender': current_user.username, 'receiver': receiver},
            {'sender': receiver, 'receiver': current_user.username}
        ]
    }).sort('timestamp', 1))

    return render_template('chat.html', receiver=receiver, messages=messages)


# Run the app
if __name__ == '__main__':
    app.run(debug=True)
