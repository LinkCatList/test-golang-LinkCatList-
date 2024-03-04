# test-golang-LinkCatList-

Ваши коллеги разрабатывают социальную сеть для инвесторов. Уже совсем скоро им нужно сдавать проект, а вся команда бэкенд-разработчиков ушла в отпуск. 

Кто-то проболтался о том, что вы знакомы с Git, HTTP, Docker, PostgreSQL и e2e-тестами. Это именно то, что нужно ребятам (а если с чем-то не знакомы, они рассчитывают на ваши навыки поиска информации)! Помогите коллегам успеть завершить проект до дедлайна и реализуйте новое HTTP API :)

Результатом выполнения данного задания является Github репозиторий с исходным кодом приложения (директория `solution`).

## Про приложение

Приложение должно представлять из себя HTTP сервер, реализующий необходимое [API](./tests/openapi.yaml). В наследие от предыдущей команды вам достался инстанс PostgreSQL, который необходимо использовать для хранения данных.

Приложение конфигурируется через переменные окружения:

- `SERVER_ADDRESS` &mdash; хост и порт, которые будет _слушать_ запущенный HTTP сервер. Например, `0.0.0.0:8080`.

- `SERVER_PORT` &mdash; содержит порт; запущенный сервер должен слушать IP `0.0.0.0` и указанный порт. Используйте эту переменную, если вам не подошел формат данных в переменной `SERVER_ADDRESS` (переданные параметры равнозначны).

- `POSTGRES_CONN` &mdash; URL-строка для подключения к PostgreSQL в формате `postgres://{username}:{password}@{host}:{5432}/{dbname}`.

- `POSTGRES_JDBC_URL` &mdash; JDBC-строка для подключения к PostgreSQL в формате `jdbc:postgresql://{host}:{port}/{dbname}`.

- `POSTGRES_USERNAME` &mdash; имя пользователя для подключения к PostgreSQL.

- `POSTGRES_PASSWORD` &mdash; пароль для подключения к PostgreSQL.

- `POSTGRES_HOST` &mdash; хост для подключения к PostgreSQL (например, `localhost`).

- `POSTGRES_PORT` &mdash; порт для подключения к PostgreSQL (например, `5432`).

- `POSTGRES_DATABASE` &mdash; имя базы данных PostgreSQL, с которой должно работать приложение.

- `RANDOM_SECRET` &mdash; псевдо-случайная последовательность из 128 символов (a-z, A-Z, 0-9), сгенерированная тестирующей системой. Можете использовать её, если вашему приложению необходим секретный ключ (например, для JWT). Если вам не требуется данное значение, можете его не использовать.

Автор приложения сам выбирает, с какими из переменных окружения ему комфортно работать.

Учитывая современные реалии, приложение будет запускаться через Docker контейнер. В репозитории присутствует Dockerfile, с помощью которого будет собираться образ приложения. 
Так как приложение совсем небольшое, мы обойдемся одним Docker контейнером, docker-compose определить не получится.

**Список используемых зависимостей (и фреймворков) не ограничен** (любая версия языка программирования, без ограничений на библиотеки), однако вы должны убедиться, что необходимые зависимости загружаются и подключаются в Dockerfile. Вы сами в праве выбирать стек вашего приложения, от вас зависит успех всего проекта!

Описание API находится ниже, но если вы хотите ознакомиться с точными требованиями, не стесняйтесь использовать Swagger и предоставленную [Open API спецификацию](./tests/openapi.yml).

Тестирование решения происходит с помощью Github CI. Для отправки решения на тестирование необходимо обновить исходный код вашего репозитория на Github (git commit & git push). 

**Вы можете редактировать файлы в директории `solution` (и `.gitignore` в корне). Если в репозитории содержатся изменения в других файлах, решение не будет принято.**

## Оценивание

Для получения баллов за группу тестов решение должно пройти все тесты из данной группы.

Группы тестов могут зависеть друг от друга. Если группа B зависит от группы A, при тестировании группы B могут использоваться эндпоинты, участвовавшие в тестировании группы A. Это свойство транзитивно!

| Название группы  | Описание                           | Баллы | От каких групп зависит |
|------------------|------------------------------------|-------|------------------------|
| 01/ping          | Успешный ответ на `/api/ping`.     | 1     |                        |
| 02/countries     | Получение и фильтрация стран.      | 6     |                        |
| 03/auth/register | Регистрация пользователей.         | 6     | - 02/countries         |
| 04/auth/sign-in  | Аутентификация и получение токена. | 7     | - 03/auth/register     |
| 05/me  | Получение и редактирование собственного профиля. | 8     | - 04/auth/sign-in     |
| 06/profiles  | Получение профиля по логину. | 5     | - 04/auth/sign-in     |
| 07/password  | Изменение пароля. | 7     | - 05/me     |
| 08/friends  | Друзья! | 12     | - 04/auth/sign-in<br>- 06/profiles    |
| 09/posts/publish  | Публикация поста и получение по ID. | 12     | - 05/me<br>- 08/friends     |
| 10/posts/feed  | Получение новостной ленты. | 16     | - 09/posts/publish     |
| 11/posts/likes  | Лайки и дизлайки. | 20     | - 10/posts/feed     |

В спорных ситуациях будет оцениваться качество кода.

На данный момент в Github CI тестирование производится на публичном наборе тестов. Данные тесты помогают провалидировать минимальную логику приложения, **но не гарантируют прохождения финальных тестов**.

## Группы тестов

### Общие требования

**У всех эндпоинтов есть префикс `/api`.**

Обратите внимание, возврат успешного ответа на `GET /api/ping` является **обязательным условием для начала тестирования приложения**.

Поступающие запросы и возвращаемые ответы должны соответствовать структуре и требованиям, описанным в [Open API](./tests/openapi.yml) спецификации. Обращайте внимание на ожидаемые status code, ограничения по длине и разрешенные символы в строках.

Если структура запроса не соответствует требованиям и описанному формату, по умолчанию возвращается код ответа 400. 
Если указан более специфичный код ответа, используйте его.

Если запрос некорректен хотя бы в одном параметре, весь запрос отвергается и признается некорректным.

### 01/ping

Достаточно реализовать возврат успешного ответа (с кодом `200`) на запрос `GET /api/ping`. Содержимое тела ответа при этом не валидируется, можно возвращать `"ok"`.

Данная логика является блокирующей для всех остальных групп тестов. 

### 02/countries

Как и в любом большом проекте у нас есть собственный словарь стран, который используется при регистрации пользователей и может учитываться рекомендательными системами и системой локализации контента.

Про каждую страну известны следующие данные:
```json
{
    "name": "полное название",
    "alpha2": "двухбуквенный код страны (в верхнем регистре)",
    "alpha3": "трехбуквенный код страны",
    "region": "географический регион"
}
```

Необходимо реализовать следующие эндпоинты:

- `GET /countries` &mdash; получить список доступных стран, доступна фильтрация по регионам. 

- `GET /countries/{alpha2}` &mdash; получить страну по её уникальному двухбуквенному коду.

Самое интересное: **для получения списка стран необходимо использовать предоставленную СУБД PostgreSQL**.

Данные находятся в таблице `countries`, которая имеет следующее определение:
```sql
CREATE TABLE countries (
    id SERIAL PRIMARY KEY,
    name TEXT,
    alpha2 TEXT,
    alpha3 TEXT,
    region TEXT
);

INSERT INTO countries (name, alpha2, alpha3, region) VALUES
    ('Åland Islands','AX','ALA','Europe'),
    ('Albania','AL','ALB','Europe'),
    ...;
```

При тестировании в Github CI база данных уже будет содержать нужный набор данных. Обратите внимание, данные в публичном и закрытом наборе тестов могут отличаться. **Приложение должно опираться на данные в СУБД, чтобы успешно пройти закрытые тесты.**

Приложение вправе менять содержимое СУБД. Если вам требуются дополнительные таблицы, создавайте их самостоятельно при старте приложения (не забудьте про `IF NOT EXISTS`).

При поиске страны по двухбуквенному коду можно реализовать регистрозависимый поиск, то есть пользователь всегда будет указывать значения в нужном регистре.

### 03/auth/register

Эндпоинт `/auth/register` используется для первичной регистрации пользователей. 

Сервер должен поддерживать базу данных пользователей, валидировать запросы и не допускать наличия пользователей с эквивалентными регистрационными данными. 

Не храните пароль пользователей в [открытом виде](https://security.stackexchange.com/questions/36833/why-should-i-hash-passwords), используется хеширование (например, bcrypt).

### 04/auth/sign-in

Эндпоинт `/auth/sign-in` предназначен для аутентификации пользователя по логину и паролю и генерации сессионного токена, 
который в дальнейшем будет использоваться для генерации запросов.

Генерируемый токен должен уникально идентифицировать пользователя и быть сложным для подбора (можно использовать JWT).

Данный токен в дальнейшем будет передаваться пользователем в заголовке `Authorization: Bearer {token}`, и приложение должно уметь понять, какой пользователь хочет сделать запрос.

Временно будем считать, что время действия токена (TTL) должно составлять от 1 до 24 часов (на усмотрение разработчика).

### 05/me

Эндпоинт `/me/profile` используется для получения и редактирования параметров собственного профиля пользователя. Действие зависит от указанного метода (`GET` и `PATCH`).

Сервер должен идентифицировать пользователя по переданному токену. Значение токена будет подставляться в заголовок `Authorization` в формате `Bearer {token}`. Например, `Authorization: Bearer $deddz$@pp...`.

В запросе на редактирование профиля передаются значения только тех полей, которые необходимо обновить.

### 06/profiles

Эндпоинт `/profiles/{login}` позволяет получить профиль другого пользователя по логину.

Обратите внимание, в некоторых ситуациях профиль пользователя получить нельзя (в зависимости от значения параметра `isPublic`). Для получения дополнительных деталей ознакомьтесь со спецификацией API.

В данной группе тестов не будет проверяться логика с друзьями пользователя.

### 07/password

С помощью `/me/updatePassword` у пользователя появляется возможность изменить пароль от своего аккаунта.

После изменения пароля:

- Аутентификация со старым паролем становится невозможной.

- Все ранее выпущенные токены должны быть отозваны. Использование старых токенов становится равнозначным использованию некорректных токенов.

После успешной смены пароля при попытке получить свой профиль со старым токеном пользователь должен получать ошибку.

### 08/friends

В приложении появляется возможность добавлять и удалять других пользователей из списка своих друзей.
И конечно же можно посмотреть список своих друзей.

Свойство быть другом &mdash; одностороннее. Если Петя добавит Машу в друзья, то профиль Пети становится доступным для Маши, даже если у Пети закрытый профиль.

Чтобы не нагружать сервера и клиенты слишком сильно, в запросах на получение списка друзей используется пагинация.
С помощью параметров `offset` и `limit` можно "постранично" получить весь список друзей, запрашивая данные порционно.

Вам потребуется запоминать дату и время последнего добавления в друзья для корректно сортировки и реализации пагинации.

### 09/posts/publish

В данной группе проверяется возможность создавать публикации со стороны пользователей.
Затрагиваемые эндпоинты:
- `/posts/new`
- `/posts/{postId}`

Сервер должен генерировать уникальные идентификаторы и запоминать время создания публикаций.

У пользователя есть доступ к своим постам, постам пользователей с публичным профилем и постам других пользователей, которые добавили данного пользователя в друзья.

В данной группе не проверяются поля с лайками и дизлайками.

### 10/posts/feed

У пользователей появилась возможность смотреть новостную ленту со своими и чужими постами. Используя пагинацию :)

Появляются запросы на `/posts/feed/my` и `/posts/feed/{login}` (значение `my` не может являться логином).

В данной группе не проверяются поля с лайками и дизлайками.

### 11/posts/likes

Самое интересное: пользователи могут поставить лайк и дизлайк публикации, к которой у них есть доступ.

Всегда запоминается последняя реакция пользователя. Если пользователь поставил лайк два раза подряд, эффект лайка остается.
Если пользователь поставил лайк, а потом дизлайк, остается реакция дизлайка.

В полях `likesCount` и `dislikesCount` необходимо отразить число лайков и дизлайков публикации, при этом от каждого пользователя учитывается только его самая последняя реакция.

## Тестирование

Для тестирования решения отразите ваши изменения в Github репозитории. Разрешено изменять только директорию `solution` и `.gitignore`, иначе тесты не будут запущены.

### Тестирование в CI

Для тестирования решений используется [Github CI](https://docs.github.com/en/actions/automating-builds-and-tests/about-continuous-integration). При отправке новых изменений в репозиторий на Github активируется тестирующий пайплайн.

Пайплайн состоит из двух этапов:
- Сборка Docker образа с вашим приложением (на основании исходного кода репозитория и Dockerfile).

- Запуск тестов. Для каждой группы тестов
    - запускаются Docker контейнеры с вашим приложением и PostgreSQL;

    - тестирующая система применяет нужные миграции к запущенному PostgreSQL (создается и заполняется только таблица `countries`, остальное должно делать ваше приложение);

    - тестирующая система дожидается успешного (`200`) ответа на `GET /api/ping`, на это дается не более 10 секунд;

    - приложение считается запущенным и начинается запуск HTTP тестов из тестируемой группы.

Проверьте, что ваше приложение готово запускать HTTP сервер на адресе, переданном в переменной окружения `SERVER_ADDRESS`. **В качестве хоста (IP) передается `0.0.0.0`, а не localhost или 127.0.0.1. Это важно!**

Также проверьте локально, что Docker образ с вашим приложением собирается (выполните `docker build .` в директории `solution`).

Существующие ограничения:

- Решению выделяется 3 vCPU, 6 GB RAM и до 1 GB дискового пространства (не учитывая PostgreSQL).
  
- В рамках тестирования ваше приложение не должно завершать работу (помните о защите от Exception, panic и прочих причинах аварийного завершения).

- Сетевое взаимодействие разрешено только с PostgreSQL и тестирующей системой. Обращаться к сторонним ресурсам по сети нельзя.

Во вкладке Actions можно найти лог тестирования, в котором будут отражены результаты запуска тестов на публичном наборе тестов.

Прохождение публичного набора тестов не дает гарантию прохождения финальных тестов.

### Локальное тестирование

Для локального тестирования вы можете пользоваться [Postman](https://www.postman.com/). В директории проекта кто-то из коллег оставил [Postman коллекцию](./tests/public-tests.json) с публичными тестами для API. Не забудьте переопределить `base_url` в переменных коллекции.

Для инициализации СУБД PostgreSQL можно использовать [заранее подготовленный скрипт](./tests/init-database.sh), из которого можно выудить SQL запросы. Обратите внимание, данный файл предназначен для локального тестирования. Тестирующая система не использует данный файл.

Чтобы локальное тестирование было максимально приближенным к тестированию в CI, мы рекомендуем запускать PostgreSQL и ваше приложение в Docker контейнерах (связанных одной сетью).

## Changelog

Как это часто бывает, заказчики проекта вносят правки в требования! 
Ваших коллег ждала та же участь... Заказчики просили передать, что они будут стараться делать как можно меньше изменений.

Но удача на нашей стороне! Коллеги будут фиксировать все правки в данном документе и вести ченджлог изменений.

Не забывайте делать `git pull --rebase`, чтобы загрузить актуальные требования в локальную версию репозитория.

### 02.03.2024

Коллеги, привет! Ваш Project Manager передал все опасения касательно сроков, поэтому мы договорились, 
что финальное тестирование будет проходить, опираясь на версию спецификации, опубликованную 3 марта 15:00 (МСК).

Напоминаем! В тестах будет проверяться только то поведение, которое было описано в README либо спецификации.

Обращаем внимание: при работе с публичным набором тестов в Postman обращайте внимание на содержимое вкладки Tests, именно там заключена логика тестирования.
Request-path в Postman изменены на `GET /api/ping`, чтобы нерелевантная информация в логах не смущала вас.

И еще немного полезных замечаний:

- Если запрос некорректен хотя бы в одном параметре, весь запрос отвергается и признается некорректным.

- Если вам нужен секретный ключ, можете (необязательно!) использовать `RANDOM_SECRET`.

- Timezone при передаче времени не так важна. Важно, чтобы счетчик времени монотонно рос и был одного формата во всех ответах backend'а.

- Чтобы отобразить число лайков и дизлайков поста, учитывайте только последнюю реакцию от каждого пользователя.

- Если структура ответа предполагает опциональность поля, сервер не должен возвращать данное поле при его отсутствии.

### 01.03.2024

Коллеги, с первым днем весны!

Напоминаем вам, что корректные логин, номер телефона, e-mail и другая подобная информация должны состоять минимум из одного символа!
А длина уникального идентификатора публикации не превышает разумных значений...

Также добавим, что в эндпоинте `/countries` если хотя бы один переданный регион является некорректным, весь запрос считается некорректным. Это общее правило: если запрос некорректен хотя бы в одном параметре, весь запрос отвергается и признается некорректным.

### 28.02.2024

Коллеги передали, что связь "друзья" является односторонней.

Если профиль пользователя закрыт, доступ к его профилю и его публикациям появляется у пользователей, кого данный пользователь добавил в друзья.

При этом если Маша добавила Петю в друзья, не значит, что Петя добавил Машу в друзья. Можно расценивать добавление в друзья как подписку.

Группа `08/friends` зависит от группы `06/profiles`.

### 27.02.2024

Коллеги, привет! Ничего критичного... Уговорили нашего Devops-инженера расширить список переменных с информацией для подключения к PostgreSQL. Смотрите секцию с описанием ENV переменных. Надеемся, теперь станет проще!

Также подсветим, что приложение должно опираться на данные в СУБД, сохранить словарь в коде приложения не получится, так как список стран может меняться! Наши QA-специалисты любят проверять работу приложения в выдуманных странах...
