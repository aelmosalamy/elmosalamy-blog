---
title: Python List Comprehensions!
author: aelmosalamy
date: 2019-01-07
tags: [python]
slug: python-list-comprehensions
---

What's up everybody! In this post I am going to show you an interesting tip which I rarely see young Pythonistas use, it's **List Comprehensions**. If you dabbled a little with Python you probably had some problems where you had to iterate over a list and perform functions to its elements on-the-run, I know. I make no sense. To clear things up let me start with a simple task. Given a list of numbers, return a list containing the squares of the original list's numbers, You might think: *"Well, That's easy!"* and write something as the following:

```python
def square(numbers):
    output = []              # Empty list for storing numbers 
    for n in numbers:        # Iterate over all numbers
        output.append(n * n) # Self-explanatory
    return output            # Look previous comment
```

Now if we run it..

```python
numbers = [1, 2, 3, 4, 5, 6, 7]
square(numbers)
# Output: [1, 4, 9, 16, 25, 36, 49]
```

It works as expected; however, It took around 7 lines to implement and execute, and since Python is built for simplicity, we've got a more *Pythonic* way to do this.

## The One Liner

```python
[x * x for x in numbers]
# Output: [1, 4, 9, 16, 25, 36, 49]
```

Magnificent, right? This is one of the simplest forms of a Python list comprehension, we iterate over each element in the list: `for x in numbers`, then apply some operations on element `x` and in our case we used `x * x` to get the square and finally we placed the whole expression inside square brackets `[]` to indicate that we want the final output in the form of a *List*. and all of this in just one line.

Let's get a bit more advanced, we can apply our comprehension selectively, ignoring all even numbers for example:

```python
>> [x * x for x in numbers if x % 2 != 0]
[1, 9, 25, 49]
```

This one is exactly like the previous one except for a little addition. We iterated over the elements in a list: `for x in numbers` and we applied a specific operation to that `x` every iteration which is `x * x`; however, we told Python to do that only if a specific condition is met which is `x % 2 != 0` which translate to *if x is not even* in simple English, What I like most about this is how natural it is written, You don't need much to get used to it, since it is written in logical order. That last sentence can be translated like this: *Give me the square of "x" for every "x" in this list of numbers only if that "x" is not even.* How much closer to English can this get? Finally, I would like to show you a 2 more examples of Python comprehensions.

You can use the exact same syntax as so:

```python
prices = {'apple': 5, 'sandwich': 15, 'almond': 3}
shopping_cart = ['apple', 'almond', 'apple', 'sandwich']
total_cost = sum([prices[item] for item in shopping_cart])
# Output: 28
```

We can even apply the exact same syntax with dictionaries, with `key:value` pairs as follows:

```python
{x: x * 5 for x in range(1, 6)}
{1: 5, 2: 10, 3: 15, 4: 20, 5: 25}
```

and there we go, we've created a *Dictionary Comprehension!*

## Conclusion

Python Comprehensions are extremely powerful tool, easy to read syntax and I find myself using it alot, one practical example is scanning a list of employees, and updating the salary of each employee in a specific team by a percentage of his current salary, in just one line.

That's it for this post, hopefully you found it useful, just keep practicing and whenever you are solving any problem, think if there is a possibility that your problem can be solved using list comprehensions, that way you can adopt it and integrate into your current Python weapons. Peace.
