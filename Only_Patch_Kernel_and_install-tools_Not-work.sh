#!/bin/bash

# Проверка на root
if [ "$(id -u)" -ne 0 ]; then
    echo "Этот скрипт должен запускаться от root. Используйте sudo!" >&2
    exit 1
fi

echo "=== Проверка и настройка репозиториев ==="
# Проверяем существование файла ubuntu.sources
if [ -f "/etc/apt/sources.list.d/ubuntu.sources" ]; then
    # Проверяем, не был ли уже создан amneziawg.sources
    if [ ! -f "/etc/apt/sources.list.d/amneziawg.sources" ]; then
        echo "Копируем ubuntu.sources в amneziawg.sources..."
        cp /etc/apt/sources.list.d/ubuntu.sources /etc/apt/sources.list.d/amneziawg.sources
        
        echo "Модифицируем amneziawg.sources (заменяем deb на deb-src)..."
        sed -i 's/deb/deb-src/' /etc/apt/sources.list.d/amneziawg.sources
    else
        echo "Файл amneziawg.sources уже существует, пропускаем копирование."
    fi
else
    echo "Файл ubuntu.sources не найден! Продолжаем без копирования."
fi

echo "=== Обновление пакетов ==="
apt update -y

echo "=== Установка зависимостей ==="
apt install -y git build-essential ncurses-dev xz-utils libssl-dev bc flex libelf-dev bison make mokutil dkms qrencode iptables

echo "=== Подготовка исходников ядра ==="
mkdir -p ~/awg-src
cd ~/awg-src || exit

echo "Клонируем amneziawg-linux-kernel-module..."
git clone https://github.com/amnezia-vpn/amneziawg-linux-kernel-module.git

echo "Ищем и скачиваем исходники ядра..."
KERNEL_VERSION=$(apt-cache search linux-source | grep -oP 'linux-source-\K\d+\.\d+\.\d+' | head -1)
if [ -z "$KERNEL_VERSION" ]; then
    echo "Не удалось определить версию linux-source. Выход."
    exit 1
fi
echo "Найдена версия ядра: $KERNEL_VERSION"
apt-get source -y linux-source-$KERNEL_VERSION

echo "=== Сборка модуля ядра ==="
cd ~/awg-src/amneziawg-linux-kernel-module/src/ || exit
ln -s ~/awg-src/linux-$KERNEL_VERSION kernel

make dkms-install
dkms add -m amneziawg -v 1.0.0
dkms build -m amneziawg -v 1.0.0
dkms install -m amneziawg -v 1.0.0

echo "=== Сборка amneziawg-tools ==="
cd ~/awg-src || exit
git clone https://github.com/amnezia-vpn/amneziawg-tools.git
cd amneziawg-tools/src/ || exit
make
make install

echo "=== Очищаем HISTORY ==="
history -c

echo "=== Готово! ==="
