import os
import re
import logging
import getpass


os.makedirs("Logs", exist_ok=True)

logging.basicConfig(
    level=logging.ERROR,
    format="%(asctime)s | [%(levelname)-7s] | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.FileHandler(
            os.path.join("Logs", "registration.log"),
            encoding="utf-8"
        ),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)


BLACKLIST = {
    "admin",
    "administrator",
    "root",
    "user",
    "test"
}


def mask_login(login):
    """Маскирует логин для журнала."""
    if not isinstance(login, str):
        return "<invalid>"

    if "@" in login:
        name, domain = login.split("@", 1)
        masked_name = name[:1] + "***" if name else "***"
        return masked_name + "@" + domain

    if login.startswith("+"):
        return "***" + login[-4:]

    if login:
        return login[:1] + "***"

    return "<empty>"


def check_login(login):
    """Проверяет логин. Возвращает None, если ошибок нет."""
    if not isinstance(login, str):
        return "Логин должен быть строкой"

    login = login.strip()

    if not login:
        return "Логин не может быть пустым"

    normalized_login = login.lower()

    if normalized_login in BLACKLIST:
        return "Логин находится в черном списке"

   
    if login.startswith("+"):
        if not re.fullmatch(r"\+\d-\d{3}-\d{3}-\d{4}", login):
            return "Неверный формат телефона"

        return None


    if "@" in login:
        email_name = login.split("@", 1)[0].lower()

        # Например, admin@mail.ru будет заблокирован
        if email_name in BLACKLIST:
            return "Логин находится в черном списке"

        if not re.fullmatch(
            r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+"
            r"(?:\.[A-Za-z0-9-]+)+",
            login
        ):
            return "Неверный формат email"

        return None

    
    if not re.fullmatch(r"[A-Za-z0-9_]{5,}", login):
        return (
            "Логин должен содержать минимум 5 символов "
            "и только латинские буквы, цифры и _"
        )

    return None


def check_password(password):
    """Проверяет пароль. Возвращает None, если ошибок нет."""
    if not isinstance(password, str):
        return "Пароль должен быть строкой"

    if len(password) < 7:
        return "Пароль должен содержать минимум 7 символов"

    allowed_password_pattern = (
        r"[А-Яа-яЁё0-9!@#$%^&*()_\-+=\[\]{};:,.<>/?\\|`~]+"
    )

    if not re.fullmatch(allowed_password_pattern, password):
        return (
            "Пароль может содержать только кириллицу, "
            "цифры и специальные символы"
        )

    if not re.search(r"[А-ЯЁ]", password):
        return "В пароле должна быть заглавная буква"

    if not re.search(r"[а-яё]", password):
        return "В пароле должна быть строчная буква"

    if not re.search(r"\d", password):
        return "В пароле должна быть цифра"

    if not re.search(
        r"[!@#$%^&*()_\-+=\[\]{};:,.<>/?\\|`~]",
        password
    ):
        return "В пароле должен быть специальный символ"

    return None


def log_validation_error(safe_login, error):
    """Записывает ошибку без пароля и подтверждения."""
    logger.error(
        "Ошибка регистрации | login=%s | result=False | error=%s",
        safe_login,
        error
    )


def validate_registration(login, password, confirmation):
    """Проверяет данные регистрации и возвращает (результат, сообщение)."""
    if isinstance(login, str):
        login = login.strip()

    safe_login = mask_login(login)

    try:
        error = check_login(login)
        if error:
            log_validation_error(safe_login, error)
            return False, error

        error = check_password(password)
        if error:
            log_validation_error(safe_login, error)
            return False, error

        if not isinstance(confirmation, str):
            error = "Подтверждение пароля должно быть строкой"
            log_validation_error(safe_login, error)
            return False, error

        if password != confirmation:
            error = "Пароль и подтверждение не совпадают"
            log_validation_error(safe_login, error)
            return False, error

        # Успешная регистрация в журнал не записывается
        return True, ""

    except Exception:
        logger.exception(
            "Внутренняя ошибка регистрации | login=%s | result=False",
            safe_login
        )
        return False, "Внутренняя ошибка программы"


if __name__ == "__main__":
    login = input("Введите логин: ")
    password = getpass.getpass("Введите пароль: ")
    confirmation = getpass.getpass("Подтвердите пароль: ")

    result, message = validate_registration(
        login,
        password,
        confirmation
    )

    print("Результат:", result)
    print("Сообщение:", message)
