#!/bin/bash

# Установка Apache2 перед запуском
sudo apt update
sudo apt install apache2 -y

# Пути к конфигурационным файлам
AWG_CONF_FILE="/etc/amnezia/amneziawg/awg0.conf"
OUTPUT_FILE="/var/www/html/amneziawg_monitor.html"

# Настройка HTTP Basic Authentication для Apache
# Создание файла с паролями для аутентификации
HTPASSWD_FILE="/etc/apache2/.htpasswd"
USERNAME="mer"
PASSWORD="mer"

# Проверка, существует ли файл с паролями, если нет - создание
if [ ! -f "$HTPASSWD_FILE" ]; then
    sudo htpasswd -cb "$HTPASSWD_FILE" "$USERNAME" "$PASSWORD"
else
    sudo htpasswd -b "$HTPASSWD_FILE" "$USERNAME" "$PASSWORD"
fi

# Добавление конфигурации в Apache для защиты доступа
APACHE_CONF_FILE="/etc/apache2/sites-available/000-default.conf"
AUTH_CONF="
<Directory \"/var/www/html\">
    AuthType Basic
    AuthName \"Restricted Content\"
    AuthUserFile $HTPASSWD_FILE
    Require valid-user
</Directory>
"

# Проверка, добавлена ли конфигурация, если нет - добавление
if ! grep -q "AuthUserFile $HTPASSWD_FILE" "$APACHE_CONF_FILE"; then
    echo "$AUTH_CONF" | sudo tee -a "$APACHE_CONF_FILE"
    sudo systemctl restart apache2
fi

# Функция для генерации отчета в HTML
generate_report() {
    # Начало HTML отчета
    echo "<!DOCTYPE html>" > $OUTPUT_FILE
    echo "<html><head><meta charset=\"UTF-8\"><title>Отчет по клиентам</title>" >> $OUTPUT_FILE
    echo "<link rel=\"stylesheet\" href=\"https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css\" />" >> $OUTPUT_FILE
    echo "<style>
        body {
            font-family: 'Nunito', sans-serif;
            background: linear-gradient(to right, #1c92d2, #f2fcfe);
            color: #333;
            margin: 0;
            padding: 0;
            display: flex;
            flex-direction: column;
            min-height: 100vh;
        }
        main {
            max-width: 80%;
            margin: 50px auto;
            padding: 40px;
            background: #ffffff;
            box-shadow: 0 10px 20px rgba(0, 0, 0, 0.2);
            border-radius: 20px;
        }
        h1 {
            font-size: 2.5em;
            color: #004080;
            text-align: center;
            margin-bottom: 25px;
        }
        p {
            font-size: 1.3em;
            color: #666;
            text-align: center;
            margin-bottom: 40px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            font-size: 1.1em;
            table-layout: fixed;
            word-wrap: break-word;
            box-shadow: 0 8px 16px rgba(0, 0, 0, 0.1);
        }
        th, td {
            border: 1px solid #ddd;
            padding: 15px;
            text-align: center;
        }
        th {
            background-color: #004080; /* Темно-синий фон */
            color: #FFFFFF; /* Белый текст */
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        tr:nth-child(even) {
            background-color: #CCE6FF; /* Светло-голубой фон */
        }
        tr:hover {
            background-color: #99CCFF; /* Чуть темнее при наведении */
            cursor: pointer;
            transition: background-color 0.3s ease;
        }
        td {
            color: #000000; /* Черный текст */
        }
        .footer {
            text-align: center;
            padding: 20px;
            background: #f5f5f5;
            color: #777;
            margin-top: auto;
            font-size: 1.1em;
            box-shadow: 0 -4px 8px rgba(0, 0, 0, 0.1);
        }
        button {
            padding: 15px 25px;
            margin: 30px auto;
            display: block;
            background-color: #004080;
            color: white;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-size: 1.2em;
            transition: background-color 0.3s ease, transform 0.3s ease;
        }
        button:hover {
            background-color: #003366;
            transform: translateY(-3px);
        }
    </style>" >> $OUTPUT_FILE
    echo "</head><body>" >> $OUTPUT_FILE

    echo "<main><p>Отчет создан: $(date)</p>" >> $OUTPUT_FILE
    echo "<h2>Клиенты</h2>" >> $OUTPUT_FILE
    echo "<table><thead><tr><th>Имя клиента</th><th>Публичный ключ</th><th>Разрешенные IP</th><th>Последнее рукопожатие</th><th>Переданные данные</th></tr></thead><tbody>" >> $OUTPUT_FILE

    # Перебор клиентов, настроенных в awg0.conf
    while read -r line; do
        if [[ "$line" =~ ^###\ Client\ (.*) ]]; then
            CLIENT_NAME="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ ^\[Peer\] ]]; then
            CLIENT_PUB_KEY=""
            CLIENT_ALLOWED_IPS=""
            CLIENT_LAST_HANDSHAKE="Недоступно"
            CLIENT_TRANSFER="Нет данных о передаче"
        elif [[ "$line" =~ PublicKey\ =\ (.*) ]]; then
            CLIENT_PUB_KEY="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ AllowedIPs\ =\ (.*) ]]; then
            CLIENT_ALLOWED_IPS="${BASH_REMATCH[1]}"

            # Получение информации о соединении и трафике с помощью `awg show`
            PEER_INFO=$(awg show awg0 | grep -A 5 "$CLIENT_PUB_KEY")
            HANDSHAKE=$(echo "$PEER_INFO" | grep 'latest handshake' | awk '{print $3, $4, $5}')
            TRANSFER=$(echo "$PEER_INFO" | grep 'transfer' | awk '{print $2, $3, $5, $6}')

            if [[ -n "$HANDSHAKE" ]]; then
                CLIENT_LAST_HANDSHAKE="$HANDSHAKE"
            else
                CLIENT_LAST_HANDSHAKE="Нет данных"
            fi

            if [[ -n "$TRANSFER" ]]; then
                TX_SIZE=$(echo "$TRANSFER" | awk '{print $1 $2}')
                RX_SIZE=$(echo "$TRANSFER" | awk '{print $3 $4}')
                CLIENT_TRANSFER="$TX_SIZE sent, $RX_SIZE received"
            else
                CLIENT_TRANSFER="Нет данных о передаче"
            fi

            # Добавление информации о клиенте в HTML таблицу
            echo "<tr class='client-row'><td>$CLIENT_NAME</td><td>$CLIENT_PUB_KEY</td><td>$CLIENT_ALLOWED_IPS</td><td>$CLIENT_LAST_HANDSHAKE</td><td>$CLIENT_TRANSFER</td></tr>" >> $OUTPUT_FILE
        fi
    done < "$AWG_CONF_FILE"

    # Закрытие HTML отчета
    echo "</tbody></table></main><footer class='footer'>&copy; 2024 AmneziaWG Monitor. Все права защищены.</footer></body></html>" >> $OUTPUT_FILE
}

# Бесконечный цикл для автоматического обновления каждые 3 секунды
trap "exit" SIGINT SIGTERM
while true
do
    generate_report
    sleep 3
done &

# Добавление скрипта в автозагрузку, чтобы он запускался при перезагрузке
SCRIPT_PATH="/root/monitorwg.sh"
CRON_JOB="@reboot $SCRIPT_PATH"

# Проверка, добавлена ли задача в cron, если нет - добавление
(crontab -l | grep -Fxq "$CRON_JOB") || (crontab -l; echo "$CRON_JOB") | crontab -
