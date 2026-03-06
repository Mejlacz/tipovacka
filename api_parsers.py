"""
api_parsers.py
Fetchery externích API (NHL, Football, TheSportsDB, UEFA) + importní logika.
"""
from __future__ import annotations
import re
from datetime import datetime
from typing import Any, Dict, List, Optional

import requests

from extensions import db
from models import (
    Match, Team, TeamAlias, Round,
    APISource, APIImportLog, MatchAPIMapping,
)



def fetch_nhl_games(season: str = "20252026", team: str = None) -> List[Dict]:
    """
    Stáhne zápasy z NHL API
    
    Args:
        season: Sezóna ve formátu YYYYYYYY (např. "20252026")
        team: Zkratka týmu (např. "BOS", "TOR") - optional
    
    Returns:
        List zápasů
    """
    try:
        # NHL API endpoint - aktualizovaný na 2025
        if team:
            url = f"https://api-web.nhle.com/v1/club-schedule/{team}/month/now"
        else:
            # Pro celou sezónu použij schedule endpoint
            url = f"https://api-web.nhle.com/v1/schedule/now"
        
        print(f"🏒 NHL API: Stahuji z {url}")
        
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        data = response.json()
        
        print(f"🏒 NHL API: Response status {response.status_code}")
        
        games = []
        
        # Parse response - NHL API struktura
        # Může být gameWeek nebo games přímo
        game_list = []
        
        if 'gameWeek' in data:
            for week in data.get('gameWeek', []):
                game_list.extend(week.get('games', []))
        elif 'games' in data:
            game_list = data.get('games', [])
        else:
            print(f"⚠️ NHL API: Neočekávaná struktura dat: {list(data.keys())}")
            return []
        
        print(f"🏒 NHL API: Nalezeno {len(game_list)} zápasů")
        
        for game in game_list:
            # Kontrola stavu zápasu
            game_state = game.get('gameState', '')
            game_type = game.get('gameType', 2)  # 2 = regular season
            
            # Parse týmy - různé možné struktury
            home_team = ""
            away_team = ""
            
            if 'homeTeam' in game and 'awayTeam' in game:
                # Nová struktura
                home_data = game.get('homeTeam', {})
                away_data = game.get('awayTeam', {})
                
                # Zkus různé možnosti názvů
                home_team = (
                    home_data.get('placeName', {}).get('default', '') or
                    home_data.get('name', {}).get('default', '') or
                    home_data.get('commonName', {}).get('default', '') or
                    home_data.get('abbrev', '')
                )
                
                away_team = (
                    away_data.get('placeName', {}).get('default', '') or
                    away_data.get('name', {}).get('default', '') or
                    away_data.get('commonName', {}).get('default', '') or
                    away_data.get('abbrev', '')
                )
            
            if not home_team or not away_team:
                print(f"⚠️ Přeskakuji zápas - chybí týmy: {game.get('id')}")
                continue
            
            # Parse datum/čas
            start_time_utc = game.get('startTimeUTC', '') or game.get('gameDate', '')
            start_time = None
            if start_time_utc:
                try:
                    start_time = datetime.fromisoformat(start_time_utc.replace('Z', '+00:00'))
                except:
                    print(f"⚠️ Chyba parsování času: {start_time_utc}")
            
            # Parse výsledek (pokud je)
            home_score = None
            away_score = None
            overtime = False
            shootout = False
            
            if game_state in ['OFF', 'FINAL']:  # Zápas skončil
                home_score = game.get('homeTeam', {}).get('score')
                away_score = game.get('awayTeam', {}).get('score')
                
                # Kontrola overtime/shootout
                period_descriptor = game.get('periodDescriptor', {})
                period_type = period_descriptor.get('periodType', 'REG')
                
                if period_type == 'OT':
                    overtime = True
                elif period_type == 'SO':
                    shootout = True
            
            games.append({
                'api_id': str(game.get('id', '')),
                'home_team': home_team,
                'away_team': away_team,
                'start_time': start_time.isoformat() if start_time else None,
                'home_score': home_score,
                'away_score': away_score,
                'overtime': overtime,
                'shootout': shootout
            })
        
        print(f"✅ NHL API: Zpracováno {len(games)} platných zápasů")
        return games
    
    except requests.exceptions.Timeout:
        print(f"❌ NHL API: Timeout při stahování")
        return []
    except requests.exceptions.ConnectionError as e:
        print(f"❌ NHL API: Chyba připojení: {e}")
        return []
    except requests.exceptions.HTTPError as e:
        print(f"❌ NHL API: HTTP chyba {e.response.status_code}: {e}")
        return []
    except Exception as e:
        print(f"❌ NHL API: Neočekávaná chyba: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return []

def fetch_football_games(league_id: int, api_key: str, season: int = None) -> List[Dict]:
    """
    Stáhne fotbalové zápasy z API-Football
    
    Args:
        league_id: ID ligy (např. 39 = Premier League)
        api_key: API klíč
        season: Rok sezóny (např. 2024)
    
    Returns:
        List zápasů
    """
    try:
        if season is None:
            # FREE plán má přístup jen k sezónám 2022-2024
            # Použij 2024 jako default (poslední dostupná na FREE)
            season = 2024
        
        print(f"⚽ API-Football: Stahuji ligu {league_id}, sezóna {season}")
        
        url = "https://v3.football.api-sports.io/fixtures"
        headers = {
            'x-rapidapi-key': api_key,
            'x-rapidapi-host': 'v3.football.api-sports.io'
        }
        params = {
            'league': league_id,
            'season': season
        }
        
        response = requests.get(url, headers=headers, params=params, timeout=15)
        
        print(f"⚽ API-Football: Response status {response.status_code}")
        
        response.raise_for_status()
        data = response.json()
        
        # Check for API errors
        if 'errors' in data and data['errors']:
            print(f"❌ API-Football errors: {data['errors']}")
            return []
        
        results_count = data.get('results', 0)
        print(f"⚽ API-Football: Nalezeno {results_count} zápasů")
        
        games = []
        
        for fixture in data.get('response', []):
            fixture_data = fixture.get('fixture', {})
            teams = fixture.get('teams', {})
            goals = fixture.get('goals', {})
            score = fixture.get('score', {})
            
            # Parse datum/čas
            date_str = fixture_data.get('date', '')
            start_time = datetime.fromisoformat(date_str.replace('Z', '+00:00')) if date_str else None
            
            # Parse výsledek
            home_score = goals.get('home')
            away_score = goals.get('away')
            
            # Kontrola extra time (použijeme jen regulární čas)
            fulltime_score = score.get('fulltime', {})
            if fulltime_score and fulltime_score.get('home') is not None:
                home_score = fulltime_score.get('home')
                away_score = fulltime_score.get('away')
            
            # Detekce extra time
            extratime_score = score.get('extratime', {})
            overtime = extratime_score.get('home') is not None
            
            games.append({
                'api_id': str(fixture_data.get('id', '')),
                'home_team': teams.get('home', {}).get('name', ''),
                'away_team': teams.get('away', {}).get('name', ''),
                'start_time': start_time.isoformat() if start_time else None,
                'home_score': home_score,
                'away_score': away_score,
                'overtime': overtime,
                'shootout': False  # Fotbal nemá nájezdy
            })
        
        print(f"✅ API-Football: Zpracováno {len(games)} zápasů")
        return games
    
    except requests.exceptions.Timeout:
        print(f"❌ API-Football: Timeout při stahování")
        return []
    except requests.exceptions.HTTPError as e:
        status_code = e.response.status_code
        print(f"❌ API-Football: HTTP chyba {status_code}")
        if status_code == 401:
            print("   → Špatný API klíč")
        elif status_code == 403:
            print("   → Přístup zakázán (zkontroluj API klíč a sezónu)")
        elif status_code == 429:
            print("   → Rate limit překročen (100 requestů/den)")
        return []
    except Exception as e:
        print(f"❌ API-Football: Neočekávaná chyba: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return []

def fetch_thesportsdb_games(league_id: int, season: str = None) -> List[Dict]:
    """
    Stáhne fotbalové zápasy z TheSportsDB (ZDARMA!)
    
    Args:
        league_id: ID ligy (např. 4631 = Chance Liga, 4480 = Champions League)
        season: Sezóna ve formátu "2024-2025" (volitelné, pokud None vrátí poslední 15 zápasů)
    
    Returns:
        List zápasů
    """
    try:
        # TheSportsDB používá API klíč "3" pro free tier (nebo "1")
        api_key = "3"
        
        if season:
            # Stáhni zápasy pro konkrétní sezónu
            url = f"https://www.thesportsdb.com/api/v1/json/{api_key}/eventsseason.php"
            params = {
                'id': league_id,
                's': season  # Formát: "2024-2025"
            }
            print(f"⚽ TheSportsDB: Stahuji ligu {league_id}, sezóna {season}")
        else:
            # Stáhni posledních 15 zápasů ligy
            url = f"https://www.thesportsdb.com/api/v1/json/{api_key}/eventspastleague.php"
            params = {'id': league_id}
            print(f"⚽ TheSportsDB: Stahuji posledních 15 zápasů ligy {league_id}")
        
        response = requests.get(url, params=params, timeout=15)
        
        print(f"⚽ TheSportsDB: Response status {response.status_code}")
        
        response.raise_for_status()
        data = response.json()
        
        events = data.get('events', [])
        
        if not events:
            print(f"⚽ TheSportsDB: Žádné zápasy nenalezeny")
            return []
        
        print(f"⚽ TheSportsDB: Nalezeno {len(events)} zápasů")
        
        games = []
        
        for event in events:
            # Parse datum/čas
            date_str = event.get('dateEvent', '')
            time_str = event.get('strTime', '') or event.get('strTimeLocal', '') or '00:00:00'
            
            # Zkombinuj datum a čas
            start_time = None
            if date_str:
                try:
                    # Formát: "2024-12-25" + "20:00:00"
                    datetime_str = f"{date_str} {time_str}"
                    start_time = datetime.strptime(datetime_str, "%Y-%m-%d %H:%M:%S")
                except Exception as e:
                    print(f"⚠️ Chyba parsování času: {date_str} {time_str} - {e}")
                    try:
                        # Zkus jen datum
                        start_time = datetime.strptime(date_str, "%Y-%m-%d")
                    except:
                        pass
            
            # Parse výsledek
            home_score = event.get('intHomeScore')
            away_score = event.get('intAwayScore')
            
            # Převeď na int pokud jsou stringy
            if home_score is not None:
                try:
                    home_score = int(home_score)
                except:
                    home_score = None
            
            if away_score is not None:
                try:
                    away_score = int(away_score)
                except:
                    away_score = None
            
            games.append({
                'api_id': str(event.get('idEvent', '')),
                'home_team': event.get('strHomeTeam', ''),
                'away_team': event.get('strAwayTeam', ''),
                'start_time': start_time.isoformat() if start_time else None,
                'home_score': home_score,
                'away_score': away_score,
                'overtime': False,  # TheSportsDB nerozlišuje prodloužení
                'shootout': False
            })
        
        print(f"✅ TheSportsDB: Zpracováno {len(games)} zápasů")
        return games
    
    except requests.exceptions.Timeout:
        print(f"❌ TheSportsDB: Timeout při stahování")
        return []
    except requests.exceptions.HTTPError as e:
        print(f"❌ TheSportsDB: HTTP chyba {e.response.status_code}")
        return []
    except Exception as e:
        print(f"❌ TheSportsDB: Neočekávaná chyba: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return []

def fetch_uefa_ucl_all_fixtures(url: Optional[str] = None) -> List[Dict]:
    """
    Scrape UEFA UCL 'All the fixtures and results' article.

    Returns list of dicts compatible with existing API import pipeline:
      {
        'api_id': str,                 # deterministic hash
        'home_team': str,
        'away_team': str,
        'start_time': ISO string (naive CZ time) or None,
        'home_score': int|None,
        'away_score': int|None,
        'overtime': bool,
        'shootout': bool
      }

    Notes:
      - Article states: "Kick-offs 21:00 CET unless stated."
      - Sometimes individual match line includes explicit time "(18:45 CET)".
      - We treat times as local (CET/CEST) naive datetimes to match the rest of the app.
    """
    try:
        target = (url or "").strip() or UEFA_UCL_ALL_FIXTURES_URL_DEFAULT
        headers = {
            "User-Agent": "Mozilla/5.0 (TipovackaBot; +https://example.invalid)",
            "Accept-Language": "en,en-US;q=0.9",
        }
        resp = requests.get(target, headers=headers, timeout=20)
        resp.raise_for_status()
        html = resp.text or ""
    except Exception as e:
        print(f"❌ UEFA UCL: Nepodařilo se stáhnout stránku: {e}")
        return []

    # Extract the main article body as plain-ish text
    # We rely on the fact that UEFA page is fairly readable even after stripping tags.
    txt = re.sub(r"<br\s*/?>", "\n", html, flags=re.I)
    txt = re.sub(r"</p\s*>", "\n", txt, flags=re.I)
    txt = re.sub(r"<[^>]+>", "", txt)
    txt = txt.replace("\xa0", " ")
    lines = [re.sub(r"\s+", " ", ln).strip() for ln in txt.splitlines()]
    lines = [ln for ln in lines if ln]

    # Default year heuristic: use current year; if we see an explicit year in any date header, we'll override as we go.
    default_year = datetime.now().year

    games: List[Dict] = []
    current_date: Optional[datetime] = None
    default_kickoff = "21:00"  # CET unless stated
    # We only start collecting after we hit "Knockout phase play-offs" or "League phase results" etc.
    in_relevant_section = False

    for ln in lines:
        # Section start
        if ln.lower().startswith("knockout phase") or ln.lower().startswith("league phase") or ln.lower().startswith("qualifying"):
            in_relevant_section = True

        if not in_relevant_section:
            continue

        # Date header?
        d = _parse_uefa_day_header(ln, default_year=default_year)
        if d:
            current_date = d
            # If line had year, update default_year
            m_year = re.search(r"\b(\d{4})\b$", ln)
            if m_year:
                try:
                    default_year = int(m_year.group(1))
                except Exception:
                    pass
            continue

        # Match lines are often like:
        # "Atalanta vs Borussia Dortmund (first leg: 0-2) (18:45 CET)"
        # "Juventus vs Galatasaray (first leg: 2-5)"
        # "Atlético de Madrid 4-1 Club Brugge (agg: 7-4)"
        if not current_date:
            continue

        # Grab explicit time if present
        time_match = re.search(r"\((\d{1,2}:\d{2})\s*CET\)", ln)
        kickoff_hm = time_match.group(1) if time_match else default_kickoff

        # Clean helper: remove bracketed notes (first leg / agg / etc.) but preserve score tokens
        ln_clean = re.sub(r"\([^)]*\)", "", ln).strip()
        ln_clean = re.sub(r"\s+", " ", ln_clean)

        home = away = None
        hs = as_ = None

        # Finished match with score: "Home 1-2 Away" (sometimes uses en dash)
        m_score = re.match(r"^(.+?)\s+(\d+)\s*[-–]\s*(\d+)\s+(.+?)$", ln_clean)
        if m_score:
            home = _normalize_team_name(m_score.group(1))
            hs = int(m_score.group(2))
            as_ = int(m_score.group(3))
            away = _normalize_team_name(m_score.group(4))
        else:
            # Upcoming match: "Home vs Away"
            m_vs = re.match(r"^(.+?)\s+vs\s+(.+?)$", ln_clean, flags=re.I)
            if m_vs:
                home = _normalize_team_name(m_vs.group(1))
                away = _normalize_team_name(m_vs.group(2))

        if not home or not away:
            continue

        # Compose start_time
        start_time = None
        try:
            hh, mm = kickoff_hm.split(":")
            start_time = datetime(current_date.year, current_date.month, current_date.day, int(hh), int(mm))
        except Exception:
            start_time = None

        # Deterministic ID – stable between match import and result import for the same tie/date
        base = f"uefa-ucl|{home.lower()}|{away.lower()}|{current_date.date().isoformat()}"
        api_id = hashlib.sha1(base.encode("utf-8")).hexdigest()

        games.append({
            "api_id": api_id,
            "home_team": home,
            "away_team": away,
            "start_time": start_time.isoformat() if start_time else None,
            "home_score": hs,
            "away_score": as_,
            "overtime": False,
            "shootout": False
        })

    print(f"🏆 UEFA UCL: Nalezeno {len(games)} zápasů (All fixtures)")
    return games

def fetch_api_games(api_source: APISource, import_type: Optional[str] = None) -> List[Dict]:
    """
    Univerzální funkce pro stažení zápasů podle typu API

    Supported:
      - nhl
      - api-football
      - thesportsdb
      - uefa-ucl (scrape UEFA "All fixtures and results")
    """
    api_type = (api_source.api_type or "").lower().strip()

    if api_type == 'nhl':
        season = api_source.league_id or "20252026"
        return fetch_nhl_games(season=season)

    if api_type == 'api-football':
        league_id = int(api_source.league_id) if api_source.league_id else 39
        api_key = api_source.api_key or ""
        return fetch_football_games(league_id=league_id, api_key=api_key)

    if api_type == 'thesportsdb':
        league_id = int(api_source.league_id) if api_source.league_id else 4631
        season = api_source.api_key if api_source.api_key else None
        return fetch_thesportsdb_games(league_id=league_id, season=season)

    if api_type == 'uefa-ucl':
        # We reuse league_id as optional URL override to avoid DB migration.
        url = api_source.league_id or None
        games = fetch_uefa_ucl_all_fixtures(url=url)

        # Filter depending on import type:
        # - matches: only upcoming (unplayed) fixtures
        # - results: only games that already have a score
        try:
            now_local = datetime.now(ZoneInfo("Europe/Prague")).replace(tzinfo=None)
        except Exception:
            now_local = datetime.now()

        if import_type == 'matches':
            filtered: List[Dict] = []
            for g in games:
                if g.get('home_score') is not None or g.get('away_score') is not None:
                    continue
                st = None
                try:
                    st = datetime.fromisoformat(g['start_time']) if g.get('start_time') else None
                except Exception:
                    st = None
                # keep only future fixtures (allow small negative drift)
                if st and st >= (now_local - timedelta(minutes=5)):
                    filtered.append(g)
            return filtered

        if import_type == 'results':
            return [g for g in games if g.get('home_score') is not None and g.get('away_score') is not None]

        return games

    print(f"❌ Neznámý typ API: {api_type}")
    return []

def import_matches_from_api(api_source: APISource, games: List[Dict], commit: bool = False) -> Tuple[int, int, List[str]]:
    """
    Importuje zápasy do databáze
    
    Args:
        api_source: API zdroj
        games: List zápasů z API
        commit: Zda commitnout změny (False = dry run)
    
    Returns:
        (imported_count, skipped_count, errors)
    """
    imported = 0
    skipped = 0
    errors = []
    
    for game in games:
        try:
            # Najdi nebo vytvoř týmy
            home_team = Team.query.filter_by(
                round_id=api_source.round_id,
                name=game['home_team']
            ).first()
            
            if not home_team:
                home_team = Team(
                    round_id=api_source.round_id,
                    name=game['home_team']
                )
                db.session.add(home_team)
                db.session.flush()
            
            away_team = Team.query.filter_by(
                round_id=api_source.round_id,
                name=game['away_team']
            ).first()
            
            if not away_team:
                away_team = Team(
                    round_id=api_source.round_id,
                    name=game['away_team']
                )
                db.session.add(away_team)
                db.session.flush()
            
            # Check jestli zápas už existuje (podle API ID)
            existing_mapping = MatchAPIMapping.query.filter_by(
                source_id=api_source.id,
                api_match_id=game['api_id']
            ).first()
            
            if existing_mapping:
                skipped += 1
                continue
            
            # Vytvoř zápas
            start_time = datetime.fromisoformat(game['start_time']) if game['start_time'] else None
            
            match = Match(
                round_id=api_source.round_id,
                home_team_id=home_team.id,
                away_team_id=away_team.id,
                start_time=start_time
            )
            db.session.add(match)
            db.session.flush()
            
            # Vytvoř mapping
            mapping = MatchAPIMapping(
                match_id=match.id,
                source_id=api_source.id,
                api_match_id=game['api_id']
            )
            db.session.add(mapping)
            
            imported += 1
        
        except Exception as e:
            errors.append(f"Chyba u zápasu {game.get('home_team')} vs {game.get('away_team')}: {str(e)}")
            skipped += 1
    
    if commit:
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            errors.append(f"Chyba při commitu: {str(e)}")
            return 0, len(games), errors
    
    return imported, skipped, errors

def import_results_from_api(api_source: APISource, games: List[Dict], commit: bool = False) -> Tuple[int, int, List[str]]:
    """
    Importuje výsledky zápasů do databáze
    
    Args:
        api_source: API zdroj
        games: List zápasů s výsledky z API
        commit: Zda commitnout změny
    
    Returns:
        (updated_count, skipped_count, errors)
    """
    updated = 0
    skipped = 0
    errors = []
    
    for game in games:
        try:
            # Najdi zápas podle API ID
            mapping = MatchAPIMapping.query.filter_by(
                source_id=api_source.id,
                api_match_id=game['api_id']
            ).first()
            
            if not mapping:
                errors.append(f"Zápas {game['api_id']} nemá mapping")
                skipped += 1
                continue
            
            match = Match.query.get(mapping.match_id)
            if not match:
                errors.append(f"Zápas ID {mapping.match_id} neexistuje")
                skipped += 1
                continue
            
            # Kontrola výsledku
            home_score = game.get('home_score')
            away_score = game.get('away_score')
            
            if home_score is None or away_score is None:
                # Zápas ještě neskončil
                skipped += 1
                continue
            
            # Kontrola overtime/shootout (pokud je nastaveno exclude_overtime)
            if api_source.exclude_overtime:
                if game.get('overtime') or game.get('shootout'):
                    errors.append(f"Zápas {game['home_team']} vs {game['away_team']} šel do prodloužení/nájezdů - kontroluj manuálně")
                    skipped += 1
                    continue
            
            # Update výsledku
            if match.home_score is None or match.away_score is None:
                match.home_score = home_score
                match.away_score = away_score
                updated += 1
            else:
                # Výsledek už existuje - skip
                skipped += 1
        
        except Exception as e:
            errors.append(f"Chyba u zápasu {game.get('api_id')}: {str(e)}")
            skipped += 1
    
    if commit:
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            errors.append(f"Chyba při commitu: {str(e)}")
            return 0, len(games), errors
    
    return updated, skipped, errors