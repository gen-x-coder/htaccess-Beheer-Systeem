Hier is een korte GitHub beschrijving:

```markdown
# .htaccess Beheer Systeem

Een eenvoudig en veilig PHP-script voor het beheren van Apache Basic Authentication via een web interface.

## Features

- Automatisch gegenereerde wachtwoordbestanden met willekeurige namen
- Gebruikersbeheer (toevoegen, verwijderen, wachtwoord wijzigen)
- Beveiliging in-/uitschakelen zonder gebruikers te verliezen
- Aanpasbare login prompt tekst
- CSRF bescherming op alle formulieren
- Geen database nodig
- Moderne, responsive interface
- Ondersteuning voor <10 gebruikers (perfect voor kleine sites)

## Installatie

1. Download `admin.php`
2. Upload naar de map die je wilt beveiligen
3. Open `admin.php` in je browser
4. Volg de setup stappen

## Vereisten

- PHP 7.4 of hoger
- Apache webserver met mod_auth_basic
- Schrijfrechten in de te beveiligen map

## Gebruik

1. **Setup**: Configureer AuthName en maak wachtwoordbestand aan
2. **Gebruikers toevoegen**: Voeg minimaal één gebruiker toe
3. **Activeren**: Activeer de beveiliging (hierna moet je inloggen)
4. **Beheren**: Gebruikers beheren via de beveiligde interface

## Beveiliging

- Bcrypt password hashing (Apache 2.4+ compatibel)
- CSRF token bescherming
- Willekeurige bestandsnamen voor wachtwoordbestanden
- Input validatie en sanitization
- Session-based beheer

## Licentie

MIT License - vrij te gebruiken voor persoonlijke en commerciële projecten
```

Wil je dat ik deze aanpas of uitbreid?
