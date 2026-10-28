# Сейф · SafeVault

[![tests](https://github.com/Vobank/SafeVault/actions/workflows/tests.yml/badge.svg)](https://github.com/Vobank/SafeVault/actions/workflows/tests.yml)

**[Русский](#русский) · [English](#english)**

> 🌐 **Язык интерфейса: только русский** · **Interface language: Russian only**

Простой шифровальщик файлов и заметок на AES-256-GCM. Пароль → ключ через scrypt. Графический интерфейс, без интернета, всё локально.

A simple file & note encryptor using AES-256-GCM. Password → key via scrypt. GUI, offline, fully local.

---

## Русский

### Что это
Приложение шифрует файлы и тексты так, что без мастер-пароля их не прочитать. Тот же класс шифрования, что в банках и мессенджерах.

### Возможности
- 🔒 Шифрование/расшифровка файлов (→ `.sejf`)
- 📝 Шифрование текстовых заметок (пароли, коды)
- 🔑 AES-256-GCM, ключ из пароля через scrypt
- 🖥 Простой GUI (Tkinter)

### Требования
- Windows, Python 3.12 (ставит зависимость сам)

### Запуск
- `Запустить Сейф.bat` — при первом запуске поставит библиотеку `cryptography`

### ⚠️ Важно
Пароль нигде не хранится — забудете, данные не вернуть. И пользуйтесь только на чистой (не заражённой) системе.

---

## English

### What it is
Encrypts files and texts so they can't be read without the master password. The same class of encryption used by banks and messengers.

### Features
- 🔒 Encrypt/decrypt files (→ `.sejf`)
- 📝 Encrypt text notes (passwords, codes)
- 🔑 AES-256-GCM, key from password via scrypt
- 🖥 Simple GUI (Tkinter)

### Requirements
- Windows, Python 3.12 (installs its dependency itself)

### Run
- `Запустить Сейф.bat` — installs the `cryptography` library on first run

### ⚠️ Important
The password is stored nowhere — if you forget it, the data is gone. Use only on a clean (non-infected) system.

---

### Технологии / Tech
Python · cryptography (AES-256-GCM, scrypt) · Tkinter

---

### Тесты / Tests
```
pip install -r requirements.txt pytest
pytest
```
Проверяют шифрование/расшифровку, отказ при неверном пароле и при подмене байтов, формат файла. / Cover encrypt/decrypt round-trips, wrong-password and tamper rejection, and the file format.
