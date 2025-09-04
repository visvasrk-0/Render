from flask import Flask, render_template, redirect, url_for
app = Flask(__name__) 

@app.route('/') 
def redirect_home():
  return redirect(url_for('home')) 

@app.route('/home') 
def home():
  return render_template('index.html') 

