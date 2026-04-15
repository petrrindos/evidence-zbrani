# Desktop build (.dmg/.exe)

Tento projekt lze zabalit jako desktop aplikaci pres Electron pro macOS i Windows.

## Pozadavky

- macOS
- Node.js 20+ (doporuceno)
- npm

## Spusteni v desktop rezimu

```bash
npm install
npm run start
```

## Vytvoreni instalatoru .dmg

```bash
npm install
npm run pack:mac
```

Vystupni soubor `.dmg` bude v adresari `dist/`.

## Vytvoreni instalatoru pro Windows (.exe)

```bash
npm install
npm run pack:win
```

Vystupni soubor `.exe` bude v adresari `dist/`.

Poznamka: Na macOS muze cross-build pro Windows vyzadovat `wine`.

## Poznamka k podepisovani

Lokalni build je nepodepsany. Pro distribuci mimo vlastni zarizeni je vhodne doplnit Apple code signing a notarizaci.
