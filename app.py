from flask import Flask, render_template

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/menu/breakfast')
def menu():
    return render_template('menu.html')

@app.route('/menu/about')
def about():
    return render_template('about.html')

@app.route('/menu/contact')
def contact():
    return render_template('contact.html')