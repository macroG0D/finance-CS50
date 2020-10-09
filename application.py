import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from datetime import datetime

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    userStocksData = {}

    user = session["user_id"]
    userSession = db.execute('SELECT * FROM users WHERE id = :user', user=user)
    stockslist = db.execute('SELECT * FROM stocks WHERE user_id = :user', user=user)

    # current_price = lookup(row['stock_symb'])

    for row in stockslist:
        current_price = lookup(row['stock_symb'])['price']
        userStocksData[row['stock_id']] = row
        userStocksData[row['stock_id']]['price'] = current_price

    return render_template("index.html", userSession=userSession, userStocksData=userStocksData)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == 'POST':

        # if empty field
        if not request.form.get('symbol') or not request.form.get('amount'):
            return apology("Empty field!", 403)
        if int(request.form.get('amount')) < 1:
            return apology("Can't buy 0 stocks!", 403)
        # if input not empty
        else:
            symbol = request.form.get("symbol")
            amount = request.form.get("amount")

            if lookup(symbol) != None:
                symbol = lookup(symbol)
                stName = symbol['name']
                stSymb = symbol['symbol']
                stPrice = symbol['price']

                # check user balance
                user = session["user_id"]
                user_id = db.execute('SELECT id FROM users WHERE id = :user', user=user)
                user_balance = db.execute("SELECT cash FROM users WHERE id = :user", user=user)
                for row in user_balance:
                    user_balance = row["cash"]

                trade_cost = int(amount) * stPrice

                # check if enough money
                if user_balance >= trade_cost:
                    user_balance -= trade_cost
                    # update user balance
                    db.execute('UPDATE users SET cash = :update_balance WHERE id = :user', update_balance=user_balance, user=user)

                    checkstockinprofile = db.execute(
                        'SELECT * FROM stocks WHERE stock_symb = :stSymb AND user_id = :user', stSymb=stSymb, user=user)
                    stockexists = False

                    # save tradedate for trades table in db
                    now = datetime.now()
                    # dd/mm/YY H:M:S
                    tradedate = now.strftime("%d/%m/%Y %H:%M:%S")

                    # trades table in db update for history
                    db.execute('INSERT INTO trades (user_id, trade_type, stock_symb, stock_name, trade_amount, price, cost, tradedate) VALUES (:user_id, :trade_type, :stock_symb, :stock_name, :trade_amount, :price, :cost, :tradedate)',
                               user_id=user, trade_type="BUY", stock_symb=stSymb, stock_name=stName, trade_amount=int(amount), price=stPrice, cost=trade_cost, tradedate=tradedate)

                    # check if stock is already in portfolio
                    for row in checkstockinprofile:
                        if row['stock_symb'] == stSymb:
                            stockexists = True

                    # update the stocks in already in portfolio
                    if stockexists:
                        db.execute("UPDATE stocks SET amount = amount + :amount WHERE user_id = :user AND stock_symb = :stSymb",
                                   amount=int(amount), user=user, stSymb=stSymb)
                        return redirect('/')

                    # if yet not in the portfolio
                    else:
                        db.execute("INSERT INTO stocks(stock_symb, stock_name, amount, user_id) VALUES (:stock_symb, :stock_name, :amount, :user_id)",
                                   stock_symb=stSymb, stock_name=stName, amount=int(amount), user_id=user)
                        return redirect('/')

                # not enough money
                else:
                    return apology("Not enough cash", 403)

            # if no share with this name— (if lookup symbol = null)
            else:
                return apology("Wrong index", 403)

    # if GET:
    else:
        return render_template("/buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    user = session["user_id"]
    table = db.execute(
        'SELECT * FROM trades, users WHERE trades.user_id = users.id AND trades.user_id = :user ORDER BY tradedate DESC', user=user)

    return render_template('history.html', table=table)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username", username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        if not request.form.get("symbol"):
            return apology("No symbol", 403)
        else:
            symbol = request.form.get("symbol")

            if lookup(symbol) != None:

                symbol = lookup(symbol)
                stName = symbol['name']
                stSymb = symbol['symbol']
                stPrice = symbol['price']
                # if symbol found in api's db:
                return render_template("/quote.html", stName=stName, stSymb=stSymb, stPrice=stPrice)
            else:
                # if symbol not exists in the api's db:
                return render_template("/quote.html", notExists='notExists')

    else:
        # if first method GET — render template with empty header:
        return render_template("/quote.html", empty='empty')


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        if not request.form.get("username"):
            return apology("must provide username", 403)
        elif not request.form.get("password"):
            return apology("must provide password", 403)
        elif request.form.get("password") != request.form.get("re_password"):
            return apology("passwords not match!", 403)
        else:
            username = request.form.get("username")
            password = request.form.get("password")

            # check if username already exists
            user = db.execute('SELECT username FROM users WHERE username = :username', username=username)
            if len(user) != 0:
                return apology("Username already exists!", 403)

            # hashing password
            hashed = generate_password_hash(password)

            # insert a hashed password into database
            db.execute("INSERT INTO users(username, hash) VALUES (:username, :password)", username=username, password=hashed)
            return login()

    else:
        # POST
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    user = session["user_id"]
    sharesList = db.execute("SELECT * FROM stocks WHERE user_id = :user", user=user)

    if request.method == "POST":

        if not request.form.get('share') or not request.form.get('amount'):
            return apology("No input", 403)
        elif int(request.form.get('amount')) < 1:
            return apology("Can't sell 0 stocks!", 403)

        else:
            amount = request.form.get('amount')
            stockname = request.form.get('share')
            current_price = lookup(stockname)['price']
            payment = current_price * float(amount)

            # update cash with payment
            db.execute("UPDATE users SET cash = cash + :payment WHERE id = :user", payment=payment, user=user)

            # save tradedate for trades table in db
            now = datetime.now()
            # dd/mm/YY H:M:S
            tradedate = now.strftime("%d/%m/%Y %H:%M:%S")

            stSymb = lookup(stockname)['symbol']
            stName = lookup(stockname)['name']
            # save tradedate for trades table in db
            now = datetime.now()
            # dd/mm/YY H:M:S
            tradedate = now.strftime("%d/%m/%Y %H:%M:%S")

            # trades table in db update for history
            db.execute('INSERT INTO trades (user_id, trade_type, stock_symb, stock_name, trade_amount, price, cost, tradedate) VALUES (:user_id, :trade_type, :stock_symb, :stock_name, :trade_amount, :price, :cost, :tradedate)',
                       user_id=user, trade_type="SELL", stock_symb=stSymb, stock_name=stName, trade_amount=int(amount), price=current_price, cost=payment, tradedate=tradedate)

            # remove soled stocks
            db.execute("UPDATE stocks SET amount = amount - :amount WHERE user_id = :user AND stock_symb = :stockname",
                       amount=amount, user=user, stockname=stockname)

            # if no stocks with this name left — remove the stocks row from table
            stocks_left = db.execute(
                "SELECT amount FROM stocks WHERE user_id = :user AND stock_symb = :stockname", user=user, stockname=stockname)
            for key in stocks_left:
                stocks_left = key['amount']
            # check if 0 or less and if True — remove from table
            if stocks_left <= 0:
                db.execute("DELETE FROM stocks WHERE user_id = :user AND stock_symb = :stockname", user=user, stockname=stockname)

            return index()

    else:
        return render_template("sell.html", sharesList=sharesList)


@app.route("/settings")
@login_required
def settings():
    """Settings"""
    if request.method == "POST":
        return change_pass()
    else:
        return render_template('settings.html')


@app.route("/change_pass", methods=["GET", "POST"])
@login_required
def change_pass():
    """Change password"""
    if request.method == "POST":
        if not request.form.get('current_pass') or not request.form.get('new_password') or not request.form.get('re_password'):
            return apology('Empty input', 403)

        # current user:
        user = session["user_id"]
        user_hash = db.execute('SELECT hash FROM users WHERE id = :user', user=user)

        current = request.form.get("current_pass")

        # check current_pass if correct
        if check_password_hash(user_hash, request.form.get("current_pass") == False):
            print(user_hash)
            print(current)
            print(check_password_hash(user_hash, current))
            return apology("invalid password", 403)

        # if not check_password_hash(rows[0]["hash"], request.form.get("password")):

        else:
            # check if new_password ==  re_password
            if not request.form.get("new_password") == request.form.get("re_password"):
                return apology("Different inputs", 403)
            # change password in db
            else:
                new_pass = request.form.get("new_password")
                hashed = generate_password_hash(new_pass)
                db.execute('UPDATE users SET hash = :hashed WHERE id = :user', hashed=hashed, user=user)
                return logout()
    else:
        return render_template('change_pass.html')


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
