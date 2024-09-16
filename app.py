import os
import re
import sqlite3

from contextlib import closing
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    user_id = session["user_id"]
    # Query database for shares owned.
    with closing(sqlite3.connect("finance.db")) as conn:
        conn.row_factory = sqlite3.Row
        with closing(conn.cursor()) as db:
            rows = db.execute(
                "SELECT * FROM shares_owned WHERE user_id = ?", (user_id,)
            ).fetchall()

            cash_total = 0
            holdings = []

            for row in rows:
                symbol = row["symbol"]
                stock = lookup(symbol)
                shares = row["shares"]
                stock_value = stock["price"]
                total_value = shares * stock_value
                holdings.append(
                    {
                        "symbol": symbol,
                        "name": stock["name"],
                        "shares": shares,
                        "price": usd(stock_value),
                        "total": usd(total_value),
                    }
                )
                cash_total += total_value

            # Query database for cash.
            user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

            cash = user["cash"]
            cash_total += cash

    return render_template(
        "index.html",
        holdings=holdings,
        cash=usd(cash),
        cash_total=usd(cash_total),
    )


@app.route("/addcash", methods=["GET", "POST"])
@login_required
def addcash():
    """Add cash"""
    if request.method == "POST":

        amount = request.form.get("amount")

        # Ensure amount was submitted.
        if not amount:
            return apology("must provide amount")

        # Ensure valid input.
        try:
            amount = int(amount)
        except:
            return apology("must provide a valid number")

        if amount <= 0:
            return apology("must provide a valid number")

        else:
            user_id = session["user_id"]

            # Query database for cash.
            with closing(sqlite3.connect("finance.db")) as conn:
                conn.row_factory = sqlite3.Row
                with closing(conn.cursor()) as db:
                    rows = db.execute(
                        "SELECT * FROM users WHERE id = ?", (user_id,)
                    ).fetchall()

                    # Select how much cash the user currently has.
                    cash = float(rows[0]["cash"])

                    # Add given amount to user's cash.
                    cash += amount
                    db.execute(
                        "UPDATE users SET cash = ? WHERE id = ?",
                        (
                            cash,
                            user_id,
                        ),
                    )
                conn.commit()

            flash("Cash has been added to your account!")
            return redirect("/")

    else:
        return render_template("addcash.html")


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol").upper()

        # Look up stock’s current price.
        stock = lookup(symbol)

        try:
            shares = int(request.form.get("shares"))
        except:
            return apology("must provide a valid number")

        # Ensure valid symbol was submitted.
        if not symbol or not stock:
            return apology("must provide a valid symbol")

        # Ensure valid number of shares was submitted.
        elif shares <= 0:
            return apology("must provide a valid number of shares")
        else:
            user_id = session["user_id"]

            # Query database for cash.
            with closing(sqlite3.connect("finance.db")) as conn:
                conn.row_factory = sqlite3.Row
                with closing(conn.cursor()) as db:
                    rows = db.execute(
                        "SELECT * FROM users WHERE id = ?", (user_id,)
                    ).fetchall()

                    # Select how much cash the user currently has.
                    cash = float(rows[0]["cash"])

                    # Calculate the total price of the shares.
                    price = shares * stock["price"]

                    # Ensure the user can afford the number of shares at the current price.
                    if price > cash:
                        return apology("insufficient funds")

                    else:
                        # Substract the price from user's current cash.
                        cash -= price

                        # Query database to record the transaction.
                        db.execute(
                            "INSERT INTO transactions (user_id, symbol, shares, transaction_type, price) VALUES (?, ?, ?, ?, ?)",
                            (
                                user_id,
                                symbol,
                                shares,
                                "Purchase",
                                price,
                            ),
                        )

                        # Check if the user already has shares from this stock.
                        owned = db.execute(
                            "SELECT * FROM shares_owned WHERE user_id = ? AND symbol = ?",
                            (
                                user_id,
                                symbol,
                            ),
                        ).fetchall()

                        if owned:
                            shares += owned[0]["shares"]
                            db.execute(
                                "UPDATE shares_owned SET shares = ? WHERE user_id = ? AND symbol = ?",
                                (
                                    shares,
                                    user_id,
                                    symbol,
                                ),
                            )
                        else:
                            db.execute(
                                "INSERT INTO shares_owned (user_id, symbol, shares) VALUES (?, ?, ?)",
                                (
                                    user_id,
                                    symbol,
                                    shares,
                                ),
                            )

                        # Query database to update user's cash.
                        db.execute(
                            "UPDATE users SET cash = ? WHERE id = ?",
                            (
                                cash,
                                user_id,
                            ),
                        )
                conn.commit()

            flash("Transaction was successful!")
            return redirect("/")
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    user_id = session["user_id"]

    # Query database for shares owned.
    with closing(sqlite3.connect("finance.db")) as conn:
        conn.row_factory = sqlite3.Row
        with closing(conn.cursor()) as db:
            rows = db.execute(
                "SELECT * FROM transactions WHERE user_id = ?", (user_id,)
            ).fetchall()

            history = []
            for row in rows:
                history.append(
                    {
                        "symbol": row["symbol"],
                        "shares": row["shares"],
                        "price": usd(row["price"]),
                        "activity": row["transaction_type"],
                        "transacted": row["time"],
                    }
                )

    return render_template("history.html", history=history)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # user reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        with closing(sqlite3.connect("finance.db")) as conn:
            conn.row_factory = sqlite3.Row
            with closing(conn.cursor()) as db:
                user = db.execute(
                    "SELECT * FROM users WHERE username = ?",
                    (request.form.get("username"),),
                ).fetchone()
                print(user)
                # Ensure username exists and password is correct
                if user is None or not check_password_hash(
                    user["hash"], request.form.get("password")
                ):
                    return apology("invalid username and/or password", 403)

            # Remember which user has logged in
            session["user_id"] = user["id"]

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

    # user reached route via POST (as by submitting a form via POST).
    if request.method == "POST":
        symbol = request.form.get("symbol").upper()
        stock = lookup(symbol)

        # Ensure symbol was submitted.
        if not symbol:
            return apology("missing symbol")

        # Ensure symbol is valid.
        elif not stock:
            return apology("invalid symbol")

        # Render page with quoted stock details.
        else:
            return render_template(
                "quoted.html",
                stock={
                    "name": stock["name"],
                    "symbol": stock["symbol"],
                    "price": usd(stock["price"]),
                },
            )

    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # Compile regex checks.
    pass_check = re.compile("^(?=.*[a-z])(?=.*[0-9]).{8,}$", re.I)
    username_check = re.compile("^.{3,15}$")

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Ensure the form was properly submitted.
        with closing(sqlite3.connect("finance.db")) as conn:
            conn.row_factory = sqlite3.Row
            with closing(conn.cursor()) as db:
                if not username or not password or not confirmation:
                    return apology("please fill out the form")

                # Ensure username is valid.
                elif not username_check.match(username):
                    return apology("invalid username")

                # Check if the username exists.
                elif db.execute(
                    "SELECT * FROM users WHERE username = ?", (username,)
                ).fetchall():
                    return apology("username already exists")

                # Ensure password is valid.
                elif not pass_check.match(password):
                    return apology("invalid password")

                # Ensure the passwords match.
                elif password != confirmation:
                    return apology("passwords do not match")

                # Register new user.
                else:
                    db.execute(
                        "INSERT INTO users (username, hash) VALUES (?, ?)",
                        (
                            username,
                            generate_password_hash(
                                password, method="pbkdf2:sha256", salt_length=8
                            ),
                        ),
                    )
            conn.commit()

            flash("You were successfully registered!")
            return redirect("/login")

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    user_id = session["user_id"]

    with closing(sqlite3.connect("finance.db")) as conn:
        conn.row_factory = sqlite3.Row
        with closing(conn.cursor()) as db:
            if request.method == "POST":
                symbol = request.form.get("symbol")

                # Look up stock’s current price.
                stock = lookup(symbol)

                # Ensure valid symbol was submitted.
                if not symbol or not stock:
                    return apology("must provide a valid symbol")

                try:
                    shares = int(request.form.get("shares"))
                except:
                    return apology("must provide a valid number")

                # Query database for user's shares.
                owned = db.execute(
                    "SELECT shares FROM shares_owned WHERE user_id = ? AND symbol = ?",
                    (
                        user_id,
                        symbol,
                    ),
                ).fetchall()

                shares_owned = int(owned[0]["shares"])

                # Ensure valid number of shares was submitted.
                if not shares:
                    return apology("must provide number of shares")
                elif shares > shares_owned or shares <= 0:
                    return apology("must provide a valid number of shares")
                else:
                    # Calculate the total worth of the shares.
                    price = shares * stock["price"]

                    # Substract shares from the user.
                    shares_owned -= shares

                    # Query database to update user's shares.
                    if shares_owned == 0:
                        db.execute(
                            "DELETE FROM shares_owned WHERE user_id = ? AND symbol = ?",
                            (
                                user_id,
                                symbol,
                            ),
                        )
                    else:
                        db.execute(
                            "UPDATE shares_owned SET shares = ? WHERE user_id = ? AND symbol = ?",
                            (
                                shares_owned,
                                user_id,
                                symbol,
                            ),
                        )

                    # Add the sale's value to user's cash.
                    user = db.execute(
                        "SELECT cash FROM users WHERE id = ?", (user_id,)
                    ).fetchone()
                    cash = float(user["cash"]) + price

                    # Query database to update user's cash.
                    db.execute(
                        "UPDATE users SET cash = ? WHERE id = ?",
                        (
                            cash,
                            user_id,
                        ),
                    )

                    # Query database to record the transaction.
                    db.execute(
                        "INSERT INTO transactions (user_id, symbol, shares, transaction_type, price) VALUES (?, ?, ?, ?, ?)",
                        (
                            user_id,
                            symbol,
                            shares,
                            "Sale",
                            price,
                        ),
                    )
                conn.commit()

                flash("Transaction was successful!")
                return redirect("/")

            else:
                # Query database for shares owned.
                rows = db.execute(
                    "SELECT symbol FROM shares_owned WHERE user_id = ?", (user_id,)
                ).fetchall()

                return render_template(
                    "sell.html", Symbols=[row["symbol"] for row in rows]
                )
