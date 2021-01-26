# This script generate a new draft post in our post directory
import os
from random import choices
from string import hexdigits
from datetime import datetime

os.chdir(os.path.dirname(os.path.realpath(__file__)))

os.chdir('content/posts')

draft_filename = '_DRAFT_' + ''.join(choices(hexdigits, k=6))
with open(f"{draft_filename}.md", 'w+') as f:
  template = f"""---
title: {draft_filename}
# change to yyyy-mm-dd
date: "{datetime.now()}" 
tags: ["tag1", "tag2", "tag3"]
description: "Keep your description here :)"
# will become /slug
slug: slug-{draft_filename}
cover: "/images/your-img-here.jpg"
draft: true
---
"""

  f.write(template)

print('Draft file created successfully: ' + draft_filename)



