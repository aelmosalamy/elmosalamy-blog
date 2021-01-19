---
title: Say Hello with Flask!
author: aelmosalamy
date: 2019-03-01
tags: ["python", "flask", "back-end"]
cover: /posts/images/cover-flask.png
---

In this post, I am going to introduce you to an interesting Python framework...

The popular web development microframework: Flask.

A framework basically controls how your code is built and deployed. A framework isn't a library. Your code calls library functions and methods; on the other hand, A framework calls your code and deploys it.

Flask is called a **microframework** because it is considered low-level compared to other web frameworks like Django; Flask provides you with the core functions and its up to you how you combine them together to create larger applications, This makes Flask very versatile and extensible.

A web framework is a framework used for web-based projects. Later, you will see how we can write our application, and then run it using Flask, which will build our application and deploy it to a local web server.

We are going to write a simple `Hello, world!` web application and gradually add features to it, as we cover the core principles of Flask in the process.

First let's install Flask; In a new terminal window, type the following:

```console
$ pip install flask
```

Now check if everything is fine and working as expected:

```console
$ flask --version
Flask 1.0.2
Python 3.6.6 (v3.6.6:4cf1f54eb7, Jun 27 2018, 03:37:03) [MSC v.1900 64 bit (AMD64)]
```

You should see a message like the one shown above.
Now I will create a new Python file, I will call it `my-app.py` and I will add the following code:

```python
from flask import Flask

app = Flask(__name__)

@app.route("/")
def index():
    return "Hello, world!"
```

This might look quite unusual, so let's break this down:

- At line 1 we imported the flask module, specifically a class called `Flask`.
- At line 3 we instantiated that class passing the `__name__` constant which refers to the module name, creating an object called `app`.
- At line 6 we defined a simple function, `index`, that takes no arguments and returns a typical "Hello, world!" string.
- At line 5 we have what we call a **function decorator**, decorators modify and extend their underlying functions, in this case our `@app.route("/")` decorator causes our `index` function to be called when the "/" route is viewed, "/" in any filesystem resembles the root; we are going to see this in action soon.

 Now I will switch back my terminal and type the following:
> **Note:** Make sure you are in the same directory where your app resides while executing all terminal commands.

```console
$ export FLASK_APP=my-app.py
$ flask run
 * Serving Flask app "my-app.py"
 * Environment: production
   WARNING: Do not use the development server in a production environment.
   Use a production WSGI server instead.
 * Debug mode: off
 * Running on http://127.0.0.1:5000/ (Press CTRL+C to quit)
```

We used `export` to set the environmental variable `FLASK_APP` to our application's name, `my-app.py`, now when we use `flask run`, Flask looks at the `FLASK_APP` environmental variable and runs our app.

You should see a line saying that our app is running at `http://127.0.0.1:5000/`.
`127.0.0.1` is the `localhost` which refers to my own computer - since the web server is running on my computer - and 5000 is the port on which my app is running at; Now open your browser and type in "127.0.0.1:5000" and you should see it, beautiful and neatly printed: Hello, world!
Notice that Flask works with pure HTML code, so instead of returning `Hello, world!` in our index function, we can return `<h1>Hello, world!</h1>`, now restart the server, reload the page and you should see Hello, world! as a nice HTML headline.

{{<figure src="/posts/images/flask-hello-world.png">}}

Additionally, Flask is serving our application at hostname `127.0.0.1:5000`, Flask works by returning different HTML pages to the viewer based on the route its on, for simplicity, let say you are visiting a webpages "http://foo.com/bar", behind the scenes you are sending a **request** to the server, demanding `/bar`, the server looks at their files and returns `/bar` to you, Flask - client-side framework - does the same, it executes Python functions based on whatever route you are visiting, then it returns a pure static HTML document to the user.

To further illustrate the idea of routes, try to open `127.0.0.1:5000/blah` and you will be stopped by a **Not Found** error message, this is because Flask returns Hello, world! only at route "/" not "/blah".

Let's create another route to clarify that concept. In your `my-app.py` file add the following code:

```python
@app.route("/<name>")
def hello(name):
    return "<h1>Hello, {}!</h1>".format(name.capitalize())
```

This technique is called a **Dynamic URL**, at Line 1 we specified a variable, `name`, between angle brackets, this variable which is a part of the URL address is then passed to our `hello` function and returned as a capitalized word inside a HTML tag, how simple!

Now restart the server and add `/pop` to your URL, you should see a `Hello, Pop!` headline, experiment with different names and notice how the page's content changes based on the route, this is especially useful when you want to create a customized experience for each user, you might have `/login/Adham` that displays `Adham`'s profile based on the route your using.

I will be writing a second post about Flask soon, It would be really appreciated if you leave me a reaction or a comment below, Thanks for sticking around. Stay tuned!
