from django.db import models


class FilesServ(models.Model):
    doc = models.FileField(max_length=255)
    file_serv = models.FileField(max_length=255)

    class Meta:
        verbose_name = 'Файл'
        verbose_name_plural = 'Файлы'


class DocServ(models.Model):
    doc = models.FileField(max_length=255)

    class Meta:
        verbose_name = 'Документ'
        verbose_name_plural = 'Документ'


class FilesDecrypt(models.Model):
    doc = models.FileField(max_length=255, upload_to='decrypto/')
    file_serv = models.FileField(max_length=255, upload_to='decrypto/')

    class Meta:
        verbose_name = 'Decrypt'
        verbose_name_plural = 'Decrypt'