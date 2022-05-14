from cryptovvb.settings import MEDIA_URL, MEDIA_ROOT
from coreapi.compat import force_text
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import EmailMessage
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import login, logout, get_user_model
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from .forms import UserRegisterForm, UserLoginForm
from .models import FilesServ, DocServ, FilesDecrypt
from .token import account_activation_token
from Crypto.PublicKey import RSA
from ellipticcurve.ecdsa import Ecdsa
from ellipticcurve.privateKey import PrivateKey
import os
import shutil


def main(request):
    return render(request, 'main.html')


def activate(request, uidb64, token):
    UserRegisterForm = get_user_model()
    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        user = UserRegisterForm.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, UserRegisterForm.DoesNotExist):
        user = None
    if user is not None and account_activation_token.check_token(user, token):
        user.is_active = True
        user.save()
        return HttpResponse('Thank you for your email confirmation. Now you can login your account.')
    else:
        return HttpResponse('Activation link is invalid!')


def register(request):
    if request.method == 'POST':
        form = UserRegisterForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.is_active = False
            form.save()

            # генерации пары ключей user1

            privatekey = RSA.generate(2048)
            filename = MEDIA_ROOT + f'\\key_user\\' + user.username + '\\' + user.username + '_privatekey.rem'
            os.makedirs(os.path.dirname(filename), exist_ok=True)
            f = open(filename, 'wb')
            f.write(bytes(privatekey.exportKey('PEM')))
            f.close()

            publickey = privatekey.publickey()
            filename = MEDIA_ROOT + f'\\key_user\\' + user.username + '\\' + user.username + '_publickey.rem'
            os.makedirs(os.path.dirname(filename), exist_ok=True)
            f = open(filename, 'wb')
            f.write(bytes(publickey.exportKey('PEM')))
            f.close()

            # генерации пары ключей user2

            privatekey = RSA.generate(2048)
            filename = MEDIA_ROOT + f'\\key_user\\' + user.username + '\\zip\\website_privatekey.rem'
            os.makedirs(os.path.dirname(filename), exist_ok=True)
            f = open(filename, 'wb')
            f.write(bytes(privatekey.exportKey('PEM')))
            f.close()

            publickey = privatekey.publickey()
            filename = MEDIA_ROOT + f'\\key_user\\' + user.username + '\\website_publickey.rem'
            f = open(filename, 'wb')
            f.write(bytes(publickey.exportKey('PEM')))
            f.close()

            current_site = get_current_site(request)
            mail_subject = f'Activation link has been sent to your email id'
            message = render_to_string('acc_active_email.html', {
                'user': user,
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': account_activation_token.make_token(user),
            })
            to_email = form.cleaned_data.get('email')
            email = EmailMessage(
                mail_subject, message, to=[to_email]
            )
            email.send()
            return redirect('main')
        else:
            pass
    else:
        form = UserRegisterForm()
    return render(request, 'register.html', {"form": form})


def user_login(request):
    if request.method == 'POST':
        form = UserLoginForm(data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            return redirect('main')
    else:
        form = UserLoginForm()
    return render(request, 'login.html', {"form": form})


def user_logout(request):
    logout(request)
    return redirect('main')


def work_archive(request):
    archive = FilesServ.objects.all()
    decrypt = FilesDecrypt.objects.all()
    style_archive = 'background-color:#045fed;'
    return render(request, 'work/archive.html',
                  {"archive": archive, "decrypt": decrypt, "style_archive": style_archive})


def work_archive_del(request, id):
    archive_del = FilesServ.objects.get(id=id)
    archive_del.delete()
    return HttpResponseRedirect("../../")


def work_archives_del(request, id):
    archive_del = FilesServ.objects.get(id=id)
    archive_del.delete()
    return HttpResponseRedirect("archive/")


def work_checking(request):
    style_checking = 'background-color:#045fed;'
    if request.method == 'POST' and request.FILES:
        FilesDecrypt.objects.create(doc=request.FILES['doc-file'], file_serv=request.FILES['zip'])
        f = open(MEDIA_ROOT + f'\\key_ecdsa\\' + str(request.FILES['zip']), "r")
        privateKey = PrivateKey.fromPem(f.read())
        f = open(MEDIA_ROOT + f'\\decrypto\\' + str(request.FILES['doc-file']), 'r', encoding='ISO-8859-1')
        plaintext = f.read()
        f.close()

        signature = Ecdsa.sign(plaintext, privateKey)

        # Generate Signature in base64. This result can be sent to Stark Bank in the request header as the Digital-Signature parameter.
        publicKey = privateKey.publicKey()
        print(publicKey.toPem())

        if Ecdsa.verify(plaintext, signature, publicKey) == True:
            messages.success(request, 'Подпись является действительной!')
        else:
            messages.error(request, 'Подпись является не действительной!')
    return render(request, 'work/checking.html', {"style_checking": style_checking})


def work_decrypt(request):
    if request.method == 'POST' and request.FILES:
        FilesDecrypt.objects.create(doc=request.FILES['doc-file'], file_serv=request.FILES['zip'])
        style_archive = 'background-color:#045fed;'
        files_zip = str(request.FILES['zip'])
        files_doc = str(request.FILES['doc-file'])
        import zipfile
        if request.user.is_authenticated:
            user = request.user
        fantasy_zip = zipfile.ZipFile(MEDIA_ROOT + f'\\decrypto\\' + files_zip)
        fantasy_zip.extractall(MEDIA_ROOT + f'\\decrypto')

        fantasy_zip.close()
        from Crypto.Cipher import AES
        from Crypto.Cipher import PKCS1_OAEP
        from Crypto.PublicKey import RSA

        # ключ сеанса дешифрования

        privatekey = RSA.importKey(open(
            MEDIA_ROOT + f'\\decrypto\\website_privatekey.rem',
            'rb').read())
        cipherrsa = PKCS1_OAEP.new(privatekey)

        f = open(MEDIA_ROOT + f'\\decrypto\\sessionkey.rem',
                 'rb')
        sessionkey = f.read()
        f.close()

        sessionkey = cipherrsa.decrypt(sessionkey)
        # сообщение для расшифровки
        f = open(MEDIA_ROOT + f'\\decrypto\\' + files_doc, 'rb')
        ciphertext = f.read()
        f.close()

        iv = ciphertext[:16]
        obj = AES.new(sessionkey, AES.MODE_CFB, iv)
        plaintext = obj.decrypt(ciphertext)
        plaintext = plaintext[16:]
        f = open(MEDIA_ROOT + f'\\decrypto\\' + files_doc, 'wb')
        f.write(bytes(plaintext))
        f.close()
        FilesServ.objects.create(doc=MEDIA_ROOT + f'\\decrypto\\' + files_doc)
        archive = FilesServ.objects.all()
        os.remove(MEDIA_ROOT + f'\\decrypto\\' + files_zip)
        return render(request, 'work/archive.html', {"style_archive": style_archive, "archive": archive})

    style_decrypt = 'background-color:#045fed;'
    return render(request, 'work/decrypt.html', {"style_decrypt": style_decrypt})


number = 0


def work_encrypt(request):
    if request.method == 'POST' and request.FILES:
        DocServ.objects.create(doc=request.FILES['doc-file'])
        style_archive = 'background-color:#045fed;'

        from Crypto.Signature import PKCS1_v1_5
        from Crypto.Hash import SHA
        from Crypto.PublicKey import RSA
        from Crypto.Cipher import PKCS1_OAEP
        if request.user.is_authenticated:
            user = request.user

        shutil.copyfile(MEDIA_ROOT + f'\\{request.FILES["doc-file"]}',
                        MEDIA_ROOT + f'\\key_user\\{user.username}\\zip\\encrypt_{request.FILES["doc-file"]}')
        # user1 подписывает сообщение своей цифровой подписью и шифрует ее открытым ключом user2
        f = open(MEDIA_ROOT + f'\\key_user\\{user.username}\\zip\\encrypt_{request.FILES["doc-file"]}', 'rb')
        plaintext = f.read()
        f.close()
        privatekey = RSA.importKey(
            open(MEDIA_ROOT + f'\\key_user\\' + user.username + '\\' + user.username + '_privatekey.rem', 'rb').read())
        myhash = SHA.new(plaintext)
        signature = PKCS1_v1_5.new(privatekey)
        signature = signature.sign(myhash)

        # шифрование подписи

        publickey = RSA.importKey(
            open(MEDIA_ROOT + f'\\key_user\\' + user.username + '\\website_publickey.rem', 'rb').read())
        cipherrsa = PKCS1_OAEP.new(publickey)
        sig = cipherrsa.encrypt(signature[:128])
        sig = sig + cipherrsa.encrypt(signature[128:])

        filename = MEDIA_ROOT + f'\\key_user\\' + user.username + '\\' + user.username + '_signature.rem'
        f = open(filename, 'wb')
        f.write(bytes(sig))
        f.close()
        # =================================
        # user1 генерирует случайный сеансовый ключ и шифрует этим ключом сообщение (с помощью симметричного алгоритма AES).
        # Сеансовый ключ шифруется открытым ключом user2 (асимметричным алгоритмом RSA).
        from Crypto.Cipher import AES
        from Crypto import Random
        from Crypto.Cipher import PKCS1_OAEP
        from Crypto.PublicKey import RSA

        # создание 256-битного ключа сеанса
        sessionkey = Random.new().read(32)  # 256 bit
        # шифрование AES сообщения
        f = open(MEDIA_ROOT + f'\\key_user\\{user.username}\\zip\\encrypt_{request.FILES["doc-file"]}', 'rb')
        plaintext = f.read()
        f.close()

        iv = Random.new().read(16)  # 128 bit
        obj = AES.new(sessionkey, AES.MODE_CFB, iv)
        ciphertext = iv + obj.encrypt(plaintext)
        f = open(MEDIA_ROOT + f'\\key_user\\{user.username}\\zip\\encrypt_{request.FILES["doc-file"]}', 'wb')
        f.write(bytes(ciphertext))
        f.close()

        # шифрование RSA сеансового ключа
        publickey = RSA.importKey(
            open(MEDIA_ROOT + f'\\key_user\\' + user.username + '\\website_publickey.rem', 'rb').read())
        cipherrsa = PKCS1_OAEP.new(publickey)
        sessionkey = cipherrsa.encrypt(sessionkey)

        filename = MEDIA_ROOT + f'\\key_user\\' + user.username + '\\zip\\sessionkey.rem'
        f = open(filename, 'wb')
        f.write(bytes(sessionkey))
        f.close()

        global number
        number += 1

        import os
        import zipfile
        if MEDIA_ROOT + f'\\key_user\\' + user.username + '\\zip' == MEDIA_ROOT + f'\\key_user\\' + user.username + '\\zip':
            print('Такой файл есть')
            fantasy_zip = zipfile.ZipFile(MEDIA_ROOT + f'\\archive' + str(number) + '.zip', 'w')

            for folder, subfolders, files in os.walk(MEDIA_ROOT + f'\\key_user\\{user.username}\\zip'):

                for file in files:
                    if file.endswith('.rem'):
                        fantasy_zip.write(os.path.join(folder, file), file, compress_type=zipfile.ZIP_DEFLATED)

            fantasy_zip.close()
            FilesServ.objects.create(doc=f'\\key_user\\{user.username}\\zip\\encrypt_{request.FILES["doc-file"]}',
                                     file_serv=f'\\archive' + str(number) + '.zip')
        else:
            fantasy_zip = zipfile.ZipFile(MEDIA_ROOT + f'\\archive.zip', 'w')

            for folder, subfolders, files in os.walk(MEDIA_ROOT + f'\\key_user\\{user.username}\\zip'):

                for file in files:
                    if file.endswith('.rem'):
                        fantasy_zip.write(os.path.join(folder, file), file, compress_type=zipfile.ZIP_DEFLATED)

            fantasy_zip.close()
            FilesServ.objects.create(doc=f'\\key_user\\{user.username}\\zip\\{request.FILES["doc-file"]}',
                                     file_serv=f'\\archive.zip')
        archive = FilesServ.objects.all()
        return render(request, 'work/archive.html', {"archive": archive, "style_archive": style_archive})
    style_encrypt = 'background-color:#045fed;'
    return render(request, 'work/encrypt.html', {"style_encrypt": style_encrypt})


def work_signature(request):
    os.makedirs(MEDIA_ROOT + f'\\key_ecdsa', exist_ok=True)
    style_signature = 'background-color:#045fed;'
    if request.method == 'POST' and request.FILES:
        FilesDecrypt.objects.create(doc=request.FILES['doc-file'])
        privateKey = PrivateKey()
        privateKey = privateKey.toPem()
        f = open(MEDIA_ROOT + f'\\key_ecdsa\\publickey.pem', "w")
        f.write(privateKey)
        f.close()
        f = open(MEDIA_ROOT + f'\\key_ecdsa\\publickey.pem', "r")
        privateKey = PrivateKey.fromPem(f.read())
        f = open(MEDIA_ROOT + f'\\decrypto\\' + str(request.FILES['doc-file']), 'r', encoding='ISO-8859-1')
        plaintext = f.read()
        f.close()
        FilesServ.objects.create(doc=request.FILES['doc-file'], file_serv=MEDIA_ROOT + f'\\key_ecdsa\\publickey.pem')
        archive = FilesServ.objects.all()
        style_archive = 'background-color:#045fed;'
        return render(request, 'work/archive.html', {"archive": archive, "style_archive": style_archive})
    return render(request, 'work/signature.html', {"style_signature": style_signature})


def cryptopro(request):
    return render(request, 'cryptopro.html')
