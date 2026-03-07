---
layout: default
---

<ul>
  {% for post in site.posts %}
    <li>
      <span style="color: #666;">{{ post.date | date: "%Y-%m-%d" }}</span> &raquo; 
      <a href="{{ post.url | relative_url }}">{{ post.title }}</a>
    </li>
  {% endfor %}
</ul>

{% if site.posts.size == 0 %}
  <p>目前还没有发布任何文章，请检查 `_posts` 文件夹。</p>
{% endif %}