from django.db import models


class User(models.Model):
    login = models.CharField(max_length=64, blank=False, null=False, unique=True)
    password = models.CharField(max_length=64, blank=False, null=False)
    