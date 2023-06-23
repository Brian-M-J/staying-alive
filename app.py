from flask import Flask, render_template, request, redirect

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        # Process the form data (e.g., store the user's information in a database)
        username = request.form['username']
        password = request.form['password']
        location = request.form['location']
        
        # Redirect the user to the sign-in page
        return redirect('/signin')
    
    return render_template('signup.html')

@app.route('/signin', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        # Process the form data (e.g., check if the user's credentials are valid)
        username = request.form['username']
        password = request.form['password']
        
        # Perform the necessary authentication checks
        
        # Redirect the user to a different page (e.g., their profile page)
        return redirect('/profile')
    
    return render_template('signin.html')

@app.route('/profile')
def profile():
    # Display the user's profile page
    return "Welcome to your profile page!"

if __name__ == '__main__':
    app.run()
