"""
Smart Parser Module
Handles parsing of match data from various formats
"""

from datetime import datetime
import re
from typing import List, Dict, Optional, Tuple


def smart_parse_matches(text: str, round_id: int = None) -> List[Dict]:
    """
    🤖 ULTRA SMART PARSER V2 - Better whitespace handling + OCR cleanup
    
    Podporované formáty:
    - Table format: "27. 2. 2026DuklaSlavia18:00" 
    - With spaces: "27. 2. 2026 Sparta - Slavia 18:00"
    - Date + time first: "27. 2. 20:00 Sparta vs Slavia"
    - CSV, Fortuna, UEFA, etc.
    - OCR from screenshots (with cleanup)
    
    Improvements:
    - Skip non-match lines (headers like "24. kolo")
    - Auto year-fill for partial dates
    - Better team splitting
    - OCR artifact cleanup
    """
    
    
    # TRY 1: Multi-line app format (with -- separators)
    if '--' in text:
        print("🎯 Detected multi-line app format")
        matches = _parse_multiline_app_format(text)
        if matches:
            print(f"✅ Multi-line parser: Found {len(matches)} matches")
            # Convert datetime to ISO
            for match in matches:
                if 'start_time' in match and isinstance(match['start_time'], datetime):
                    match['start_time'] = match['start_time'].isoformat()
            return matches
    
    # Step 1: Clean OCR artifacts (vice>, |, extra whitespace)
    text = _clean_ocr_artifacts(text)
    
    # Step 2: Handle table copy/paste (all lines joined)
    text = _split_joined_lines(text)
    
    matches = []
    lines = text.strip().split('\n')
    
    print(f"🤖 Smart Parser V2: Zpracovávám {len(lines)} řádků")
    
    for line_num, line in enumerate(lines, 1):
        # Don't normalize whitespace yet - some formats need it
        line_raw = line.strip()
        
        if not line_raw or len(line_raw) < 5:
            continue
        
        # Skip lines that are obviously not matches
        if line_raw.lower() in ['kolo', 'round', 'zápasy', 'matches']:
            print(f"⏭️ Přeskakuji header: {line_raw}")
            continue
        if re.match(r'^\d+\.\s*kolo', line_raw, re.I):
            print(f"⏭️ Přeskakuji kolo header: {line_raw}")
            continue
        
        match_data = _parse_single_line(line_raw, line_num)
        if match_data:
            # Convert datetime to ISO string for JSON
            if 'start_time' in match_data and match_data['start_time']:
                if isinstance(match_data['start_time'], datetime):
                    match_data['start_time'] = match_data['start_time'].isoformat()
            
            matches.append(match_data)
    
    print(f"✅ Smart Parser V2: Nalezeno {len(matches)} zápasů")
    return matches




def _clean_ocr_artifacts(text: str) -> str:
    """
    Clean up OCR artifacts from screenshot text
    
    OCR often adds extra characters like:
    - "vice >" or "více>" (from web UI buttons)
    - "|" pipes
    - Extra whitespace
    - Weird unicode characters
    
    Returns cleaned text ready for parsing
    """
    lines = text.strip().split('\n')
    cleaned_lines = []
    
    for line in lines:
        # Remove common OCR artifacts
        # Remove "vice >", "více>", "vic>", "víc>" and similar
        line = re.sub(r'\s*v[ií]ce?\s*>?\s*', ' ', line, flags=re.IGNORECASE)
        
        # Remove pipe symbols (often from table borders)
        line = re.sub(r'\s*\|\s*', ' ', line)
        
        # Remove extra whitespace between words (but keep spaces)
        line = re.sub(r'\s+', ' ', line)
        
        # Remove leading/trailing whitespace
        line = line.strip()
        
        if line:
            cleaned_lines.append(line)
    
    result = '\n'.join(cleaned_lines)
    print(f"🧹 OCR cleanup: {len(lines)} lines → {len(cleaned_lines)} cleaned lines")
    return result

def _parse_multiline_app_format(text: str) -> List[Dict]:
    """
    Parse multi-line format from app/website:
    
    07.03. 15:00
    Bohemians
    Slovan Liberec
    --
    """
    matches = []
    blocks = text.split('--')
    current_year = 2026
    
    for block in blocks:
        lines = [line.strip() for line in block.strip().split('\n') if line.strip()]
        
        if len(lines) < 3:
            continue
        
        # Skip "25. kolo" headers
        if lines[0].lower().endswith('kolo'):
            lines = lines[1:]
        
        if len(lines) < 3:
            continue
        
        datetime_line = lines[0]
        home_team = lines[1]
        away_team = lines[2]
        
        # Parse "07.03. 15:00"
        match = re.match(r'(\d{2})\.(\d{2})\.\s+(\d{1,2}):(\d{2})', datetime_line)
        if not match:
            continue
        
        day = int(match.group(1))
        month = int(match.group(2))
        hour = int(match.group(3))
        minute = int(match.group(4))
        
        try:
            dt = datetime(current_year, month, day, hour, minute)
            matches.append({
                'home_team': home_team.strip(),
                'away_team': away_team.strip(),
                'start_time': dt,
            })
        except ValueError:
            continue
    
    return matches

def _split_joined_lines(text: str) -> str:
    """
    CRITICAL FIX: Table copy/paste joins all lines
    
    New strategy: Extract complete match patterns
    Pattern: DD. MM. YYYY + text + time/score (N:N or NN:NN)
    """
    
    # Skip if already properly formatted
    lines = text.split('\n')
    if len(lines) > 3:
        return text
    
    # Rejoin text
    text_joined = ' '.join(lines)
    
    # Pattern for complete match:
    # Date + any text + final number:number
    # Use non-greedy match and lookahead
    pattern = r'(\d{1,2}\.\s*\d{1,2}\.\s*\d{4}.*?\d{1,2}:\d{1,2})(?=\d{1,2}\.\s*\d{1,2}\.\s*\d{4}|$)'
    
    matches = re.findall(pattern, text_joined)
    
    if len(matches) >= 2:
        # Add any header before first match
        parts = []
        first_match_pos = text_joined.find(matches[0])
        if first_match_pos > 0:
            header = text_joined[:first_match_pos].strip()
            if header:
                parts.append(header)
        
        # Add all matches
        for match in matches:
            parts.append(match.strip())
        
        if len(parts) > 1:
            result = '\n'.join(parts)
            print(f"🔧 Extracted {len(parts)} lines from joined input")
            return result
    
    return text






def _parse_single_line(line: str, line_num: int = 0) -> Optional[Dict]:
    """
    IMPROVED: Better handling of different formats
    
    Priority:
    1. Table format (no spaces): 27. 2. 2026DuklaSlavia18:00
    2. Date with spaces: 27. 2. 2026 Dukla - Slavia 18:00
    3. Other formats
    """
    
    # TRY 1: Table format FIRST (before whitespace normalization!)
    result = _parse_table_format(line)
    if result:
        return result
    
    # TRY 2: Now normalize whitespace for other formats
    line_normalized = re.sub(r'\s+', ' ', line.replace('\t', ' ')).strip()
    
    # TRY 3: Compact date format (OCR): "7.3.2026 Team1 Team2 15:00"
    if len(parts) >= 4 and _is_date(parts[0]):
        result = _parse_compact_date_format(line_normalized, parts)
        if result:
            return result
    
    # TRY 4: Date at start with spaces
    # (Original TRY 3 now TRY 4) # Date at start with spaces
    parts = line_normalized.split()
    
    # "27. 2. 2026 Dukla - Slavia 18:00"
    if len(parts) >= 3 and _is_date(' '.join(parts[:3])):
        return _parse_date_first_format(line_normalized, parts)
    
    # "27. 2. 20:00 Sparta vs Slavia"
    if len(parts) >= 4:
        potential_date = ' '.join(parts[:2])
        potential_time = parts[2]
        
        if _is_date(potential_date) and re.match(r'^\d{1,2}:\d{2}$', potential_time):
            return _parse_date_time_first(line_normalized, parts)
    
    # TRY 5: Other parsers
    parsers = [
        _parse_fortuna_style,
        _parse_uefa_style,
        _parse_csv_style,
        _parse_pipe_style,
        _parse_score_style,
        _parse_vs_style,
        _parse_dash_style,
    ]
    
    for parser in parsers:
        try:
            result = parser(line_normalized)
            if result:
                return result
        except Exception:
            continue
    
    print(f"⚠️ Nepodařilo se parsovat řádek {line_num}: {line[:50]}")
    return None




def _parse_compact_date_format(line: str, parts: List[str]) -> Optional[Dict]:
    """
    Parse compact date format (common from OCR):
    "7.3.2026 Teplice Dukla 15:00"
    Format: DATE TEAM1 TEAM2 TIME
    """
    date_str = parts[0]
    rest_parts = parts[1:]
    
    dt = _parse_datetime(date_str)
    if not dt:
        return None
    
    # Check if last part is time
    time_str = None
    if rest_parts and re.match(r'^\d{1,2}:\d{2}$', rest_parts[-1]):
        time_str = rest_parts[-1]
        team_parts = rest_parts[:-1]
    else:
        team_parts = rest_parts
    
    if len(team_parts) < 2:
        return None
    
    # Split teams
    if len(team_parts) == 2:
        home_team, away_team = team_parts[0], team_parts[1]
    else:
        teams_text = ' '.join(team_parts)
        home_team, away_team = _smart_split_teams(teams_text)
        if not home_team or not away_team:
            mid = len(team_parts) // 2
            home_team = ' '.join(team_parts[:mid])
            away_team = ' '.join(team_parts[mid:])
    
    # Add time to datetime
    if time_str and dt:
        try:
            time_obj = datetime.strptime(time_str, "%H:%M").time()
            dt = dt.replace(hour=time_obj.hour, minute=time_obj.minute)
        except:
            pass
    
    return {
        'home_team': home_team.strip(),
        'away_team': away_team.strip(),
        'start_time': dt,
    }



def _parse_date_first_format(line: str, parts: List[str]) -> Optional[Dict]:
    """Parse: 27. 2. 2026 Dukla Slavia 18:00 OR 27. 2. 2026 Dukla Slavia 0:2"""
    
    date_str = ' '.join(parts[:3])  # "27. 2. 2026"
    rest = ' '.join(parts[3:])       # "Dukla Slavia 18:00" or "Dukla Slavia 0:2"
    
    dt = _parse_datetime(date_str)
    
    # Check for time/score at end
    time_or_score_match = re.search(r'(\d{1,2}):(\d{1,2})$', rest)
    
    is_score = False
    home_score = None
    away_score = None
    
    if time_or_score_match:
        first_num = int(time_or_score_match.group(1))
        second_num = int(time_or_score_match.group(2))
        full_match = time_or_score_match.group(0)
        teams_part = rest[:rest.rfind(full_match)].strip()
        
        # Determine if it's time or score
        if first_num >= 10 and first_num <= 23:
            is_score = False  # Likely time
        elif second_num in [0, 15, 30, 45] and first_num <= 23:
            is_score = False  # Common time minutes
        elif first_num < 10 and second_num < 10:
            is_score = True  # Both small - likely score
        else:
            is_score = first_num > 23 or second_num > 59
        
        if is_score:
            home_score = first_num
            away_score = second_num
        else:
            # It's a time
            if dt:
                try:
                    time_obj = datetime.strptime(full_match, "%H:%M").time()
                    dt = dt.replace(hour=time_obj.hour, minute=time_obj.minute)
                except:
                    pass
    else:
        teams_part = rest
    
    # Parse teams
    if ' - ' in teams_part:
        teams = teams_part.split(' - ', 1)
    elif ' vs ' in teams_part.lower():
        teams = re.split(r'\s+vs\s+', teams_part, flags=re.I, maxsplit=1)
    else:
        # Try to split by space
        teams = teams_part.split()
        if len(teams) < 2:
            return {
                'home_team': teams_part.strip(),
                'away_team': '',
                'start_time': dt,
            }
    
    if len(teams) >= 2:
        result = {
            'home_team': teams[0].strip(),
            'away_team': teams[1].strip() if len(teams) > 1 else teams[-1].strip(),
            'start_time': dt,
        }
        
        if home_score is not None:
            result['home_score'] = home_score
            result['away_score'] = away_score
        
        return result
    
    return None



def _parse_date_time_first(line: str, parts: List[str]) -> Optional[Dict]:
    """Parse: 27. 2. 20:00 Sparta vs Slavia"""
    
    date_str = ' '.join(parts[:2])  # "27. 2."
    time_str = parts[2]              # "20:00"
    rest = ' '.join(parts[3:])       # "Sparta vs Slavia"
    
    dt = _parse_datetime(date_str + ' ' + time_str)
    
    # Parse teams
    if ' - ' in rest:
        teams = rest.split(' - ', 1)
    elif ' vs ' in rest.lower():
        teams = re.split(r'\s+vs\s+', rest, flags=re.I, maxsplit=1)
    else:
        return None
    
    if len(teams) >= 2:
        return {
            'home_team': teams[0].strip(),
            'away_team': teams[1].strip(),
            'start_time': dt,
        }
    
    return None





def _parse_table_format(line: str) -> Optional[Dict]:
    """
    IMPROVED: Parse table copy/paste - handles NO SPACES between parts
    
    Examples:
    - 27. 2. 2026DuklaSlavia18:00      (time)
    - 27. 2. 2026DuklaSlavia0:2        (score)
    - 28. 2. 2026Ml. Boleslav__Jablonec__15:00
    """
    
    # Pattern: DATE (required) + TEAMS (any) + TIME/SCORE (required)
    
    # Match date at start
    date_match = re.match(r'^(\d{1,2}\.\s*\d{1,2}\.\s*\d{4})', line)
    if not date_match:
        return None
    
    date_str = date_match.group(1)
    rest = line[len(date_str):].strip()
    
    # Match time OR score at end
    # Time: HH:MM (hour 0-23, minute 00-59)
    # Score: N:N (any digits)
    time_score_match = re.search(r'(\d{1,2}:\d{1,2})$', rest)
    if not time_score_match:
        return None
    
    time_or_score = time_score_match.group(1)
    teams_part = rest[:rest.rfind(time_or_score)].strip()
    
    if not teams_part:
        return None
    
    # Determine if it's time or score
    parts = time_or_score.split(':')
    hour_or_home = int(parts[0])
    min_or_away = int(parts[1])
    
    # Heuristic: If first number > 23 OR second number > 59, it's probably score
    # OR if both numbers are single digit and < 10, could be score
    is_score = False
    is_time = False
    
    # Definite time: HH:MM format where HH in 0-23 and MM in 00-59
    if 0 <= hour_or_home <= 23 and 0 <= min_or_away <= 59:
        # Could be time... but also could be low score like 2:1
        # Check: if MM is 00, 15, 30, 45 → likely time
        if min_or_away in [0, 15, 30, 45]:
            is_time = True
        # If HH >= 10, likely time (games don't usually have 10+ goals)
        elif hour_or_home >= 10:
            is_time = True
        # If both small (< 10), likely score
        else:
            is_score = True
    else:
        # Outside valid time range → score
        is_score = True
    
    # Parse teams
    if '__' in teams_part:
        parts = [p.strip() for p in teams_part.split('__') if p.strip()]
        if len(parts) >= 2:
            home_team = parts[0]
            away_team = parts[1]
        else:
            return None
    else:
        home_team, away_team = _smart_split_teams(teams_part)
        if not home_team or not away_team:
            return None
    
    # Build result
    result = {
        'home_team': home_team,
        'away_team': away_team,
    }
    
    if is_time:
        # Parse as time
        try:
            dt = datetime.strptime(f"{date_str} {time_or_score}", "%d. %m. %Y %H:%M")
            result['start_time'] = dt
        except:
            result['start_time'] = None
    else:
        # Parse as score
        result['home_score'] = hour_or_home
        result['away_score'] = min_or_away
        # Parse just the date (no time)
        try:
            dt = datetime.strptime(date_str, "%d. %m. %Y")
            result['start_time'] = dt
        except:
            result['start_time'] = None
    
    return result




def _smart_split_teams(text: str) -> Tuple[Optional[str], Optional[str]]:
    """
    IMPROVED: Smart split teams from text without separator
    
    Examples:
    - "DuklaSlavia" → "Dukla", "Slavia"
    - "SpartaOstrava" → "Sparta", "Ostrava"
    - "Ml. BoleslavJablonec" → "Ml. Boleslav", "Jablonec"
    """
    
    known_teams = [
        # Longer names first for greedy matching
        'Ml. Boleslav', 'Mladá Boleslav',
        'Hradec Kr.', 'Hradec Králové', 'Hradec',
        'FK Dukla Praha', 'SK Slavia Praha', 'AC Sparta Praha',
        'FC Viktoria Plzeň', 'FC Zlín', 'FC Slovan Liberec',
        'FC Baník Ostrava', 'FK Teplice', 'FK Jablonec',
        'MFK Karviná', '1.FC Slovácko', '1. FC Slovácko', 'FK Pardubice',
        'SK Sigma Olomouc', 'Bohemians Praha 1905',
        'FK Mladá Boleslav', 'FC Hradec Králové',
        # Short names
        'Dukla', 'Slavia', 'Sparta', 'Plzeň', 'Zlín',
        'Liberec', 'Ostrava', 'Baník', 'Teplice', 'Jablonec',
        'Karviná', 'Slovácko', 'Pardubice', 'Olomouc', 'Sigma',
        'Bohemians',
    ]
    
    # Try to match known team from start
    for team in sorted(known_teams, key=len, reverse=True):
        if text.startswith(team):
            home = team
            away = text[len(team):].strip()
            
            # Check if away is also a known team
            for away_team in known_teams:
                if away == away_team or away.startswith(away_team):
                    return home, away_team
            
            # Try away as-is
            if away:
                return home, away
    
    # Fallback: split at second capital letter
    capitals = [i for i, c in enumerate(text) if c.isupper()]
    if len(capitals) >= 2:
        split_pos = capitals[1]
        return text[:split_pos], text[split_pos:]
    
    return None, None




def _parse_fortuna_style(line: str) -> Optional[Dict]:
    """Fortuna Liga: #22 14/02/26Sat 15:00 DUK 0:0 FCZ"""
    pattern = r'#(\d+)\s+(\d{2})/(\d{2})/(\d{2})(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+(\d{1,2}):(\d{2})\s+([A-Z]{3,4})\s+(?:(\d+):(\d+)|[-–])\s+([A-Z]{3,4})'
    m = re.search(pattern, line)
    if not m:
        return None

    day, month, year_short = int(m.group(2)), int(m.group(3)), int(m.group(4))
    hour, minute = int(m.group(5)), int(m.group(6))
    home_code, away_code = m.group(7), m.group(10)
    home_score = int(m.group(8)) if m.group(8) else None
    away_score = int(m.group(9)) if m.group(9) else None

    year = 2000 + year_short if year_short < 50 else 1900 + year_short

    # Team code to name
    team_map = {
        'ACS': 'AC Sparta Praha', 'SKS': 'SK Slavia Praha',
        'PLZ': 'FC Viktoria Plzeň', 'LIB': 'FC Slovan Liberec',
        'FCB': 'FC Baník Ostrava', 'MBL': 'FK Mladá Boleslav',
        'FKJ': 'FK Jablonec', 'BOH': 'Bohemians Praha 1905',
        'FCS': '1.FC Slovácko', 'SIG': 'SK Sigma Olomouc',
        'TEP': 'FK Teplice', 'HKR': 'FC Hradec Králové',
        'PCE': 'FK Pardubice', 'KAR': 'MFK Karviná',
        'FCZ': 'FC Zlín', 'DUK': 'FK Dukla Praha',
    }

    return {
        'home_team': team_map.get(home_code, home_code),
        'away_team': team_map.get(away_code, away_code),
        'start_time': datetime(year, month, day, hour, minute),
        'home_score': home_score,
        'away_score': away_score,
    }




def _parse_uefa_style(line: str) -> Optional[Dict]:
    """UEFA: Juventus 2-1 Galatasaray (18:45 CET)"""
    # S časem
    pattern = r'(.+?)\s+(\d+)[-–:](\d+)\s+(.+?)\s*\((\d{1,2}):(\d{2})'
    m = re.search(pattern, line)
    if m:
        home = m.group(1).strip()
        away = m.group(4).strip()
        hour, minute = int(m.group(5)), int(m.group(6))
        return {
            'home_team': home,
            'away_team': away,
            'home_score': int(m.group(2)),
            'away_score': int(m.group(3)),
            'start_time': datetime.now().replace(hour=hour, minute=minute),
        }

    # Bez času
    pattern = r'(.+?)\s+(\d+)[-–](\d+)\s+(.+?)$'
    m = re.search(pattern, line)
    if m:
        return {
            'home_team': m.group(1).strip(),
            'away_team': m.group(4).strip(),
            'home_score': int(m.group(2)),
            'away_score': int(m.group(3)),
        }

    return None




def _parse_csv_style(line: str) -> Optional[Dict]:
    """CSV: Sparta,Slavia,2,1,14.2.2026 20:00

    Robustnější:
    - umí ignorovat úvodní kódový sloupec (např. "Ml."/"ACS"/"MBL")
    - umí ignorovat úvodní datumový sloupec (např. "27. 2. 2026,Sparta,Slavia,18:00")
    - umí sloučit rozpadlý název týmu typu "Ml." + "Boleslav"
    """
    if ',' not in line:
        return None

    parts = [p.strip() for p in line.split(',') if p.strip()]
    if len(parts) < 2:
        return None

    def _looks_like_code(tok: str) -> bool:
        t = (tok or '').strip()
        if not t or ' ' in t or len(t) > 5:
            return False
        if re.match(r'^[A-Za-z]{1,4}\.?$', t):
            return True
        if t.isupper() and re.match(r'^[A-Z0-9]{2,5}$', t):
            return True
        return False

    leading_dt = None
    if len(parts) >= 3 and _is_date(parts[0]):
        leading_dt = parts[0]
        parts = parts[1:]

    if len(parts) >= 3 and _looks_like_code(parts[0]) and (len(parts[1]) >= 5 or ' ' in parts[1]):
        parts = parts[1:]

    if len(parts) >= 3 and parts[0].endswith('.') and len(parts[0]) <= 4 and ' ' not in parts[1] and parts[1].isalpha():
        merged = f"{parts[0]} {parts[1]}"
        parts = [merged] + parts[2:]

    if len(parts) < 2:
        return None

    result: Dict[str, Any] = {'home_team': parts[0], 'away_team': parts[1]}
    tail = parts[2:]

    def _is_probable_time(tok: str) -> bool:
        # HH:MM typical kick-off time (minutes usually 00/15/30/45)
        m = re.match(r'^(\d{1,2}):(\d{2})$', (tok or '').strip())
        if not m:
            return False
        hh = int(m.group(1))
        mm = int(m.group(2))
        return 0 <= hh <= 23 and 0 <= mm <= 59 and mm in (0, 15, 30, 45) and hh >= 8

    def _is_score_colon(tok: str) -> bool:
        return bool(re.match(r'^(\d{1,2}):(\d{1,2})$', (tok or '').strip()))

    def _apply_dt_from_tail(tokens: list[str]) -> None:
        nonlocal result, leading_dt
        if not tokens:
            return
        last = tokens[-1].strip()

        # if we have leading date from first column, allow time-only last column
        if leading_dt and _is_probable_time(last):
            dt = _parse_datetime(f"{leading_dt} {last}")
            if dt:
                result['start_time'] = dt
            return

        # full datetime in last token
        dt = _parse_datetime(last)
        if dt:
            result['start_time'] = dt

    # --- score/time parsing in tail ---
    if tail:
        # Handle scores like "0:2"
        if _is_score_colon(tail[0]):
            try:
                hs, aw = tail[0].split(':', 1)
                result['home_score'] = int(hs)
                result['away_score'] = int(aw)
            except Exception:
                pass
            _apply_dt_from_tail(tail[1:])
            # If we have only date (no time), set a sensible default so the match is tipovatelný.
            if leading_dt and 'start_time' not in result:
                dt = _parse_datetime(f"{leading_dt} 18:00")
                if dt:
                    result['start_time'] = dt
            return result

        # Handle numeric scores "2,1"
        if len(tail) >= 2 and re.match(r'^\d+$', tail[0]) and re.match(r'^\d+$', tail[1]):
            result['home_score'] = int(tail[0])
            result['away_score'] = int(tail[1])
            _apply_dt_from_tail(tail[2:])
            return result

    _apply_dt_from_tail(tail)
    if leading_dt and 'start_time' not in result:
        # date-only without time; keep empty for preview unless you want default time
        dt = _parse_datetime(f"{leading_dt} 18:00")
        if dt:
            result['start_time'] = dt

    return result





def _parse_pipe_style(line: str) -> Optional[Dict]:
    """Pipe separated: Sparta|Slavia|2|1|14.2.2026 20:00

    Robustnější:
    - umí ignorovat úvodní kódový sloupec (např. "Ml."/"ACS"/"MBL")
    - umí ignorovat úvodní datumový sloupec (např. "27. 2. 2026 | Sparta | Slavia | 18:00")
    - umí sloučit rozpadlý název týmu typu "Ml." + "Boleslav"
    """
    if '|' not in line:
        return None

    parts = [p.strip() for p in line.split('|') if p.strip()]
    if len(parts) < 2:
        return None

    def _looks_like_code(tok: str) -> bool:
        t = (tok or '').strip()
        if not t or ' ' in t or len(t) > 5:
            return False
        if re.match(r'^[A-Za-z]{1,4}\.?$', t):
            return True
        if t.isupper() and re.match(r'^[A-Z0-9]{2,5}$', t):
            return True
        return False

    leading_date = None
    if len(parts) >= 3 and _is_date(parts[0]):
        leading_date = parts[0]
        parts = parts[1:]

    if len(parts) >= 3 and _looks_like_code(parts[0]) and (len(parts[1]) >= 5 or ' ' in parts[1]):
        parts = parts[1:]

    if len(parts) >= 3 and parts[0].endswith('.') and len(parts[0]) <= 4 and ' ' not in parts[1] and parts[1].isalpha():
        merged = f"{parts[0]} {parts[1]}"
        parts = [merged] + parts[2:]

    if len(parts) < 2:
        return None

    result: Dict[str, Any] = {'home_team': parts[0], 'away_team': parts[1]}
    tail = parts[2:]

    def _is_probable_time(tok: str) -> bool:
        m = re.match(r'^(\d{1,2}):(\d{2})$', (tok or '').strip())
        if not m:
            return False
        hh = int(m.group(1))
        mm = int(m.group(2))
        return 0 <= hh <= 23 and 0 <= mm <= 59 and mm in (0, 15, 30, 45) and hh >= 8

    def _is_score_colon(tok: str) -> bool:
        return bool(re.match(r'^(\d{1,2}):(\d{1,2})$', (tok or '').strip()))

    # If we have leading date and the next token is a time, treat it as kick-off time
    if leading_date and tail and _is_probable_time(tail[0]):
        dt = _parse_datetime(f"{leading_date} {tail[0]}")
        if dt:
            result['start_time'] = dt
        tail = tail[1:]

    # Handle score in format "0:2" (very common in pasted tables)
    if tail and _is_score_colon(tail[0]) and not _is_probable_time(tail[0]):
        try:
            hs, aw = tail[0].split(':', 1)
            result['home_score'] = int(hs)
            result['away_score'] = int(aw)
        except Exception:
            pass
        tail = tail[1:]
        if leading_date and 'start_time' not in result:
            dt = _parse_datetime(f"{leading_date} 18:00")
            if dt:
                result['start_time'] = dt

    # Handle numeric scores "2|1"
    if len(tail) >= 2 and re.match(r'^\d+$', str(tail[0])) and re.match(r'^\d+$', str(tail[1])):
        result['home_score'] = int(tail[0])
        result['away_score'] = int(tail[1])
        tail = tail[2:]

    # Remaining tail may contain full datetime
    if tail:
        dt = _parse_datetime(tail[0])
        if dt:
            result['start_time'] = dt
        elif leading_date and _is_probable_time(tail[0]):
            dt = _parse_datetime(f"{leading_date} {tail[0]}")
            if dt:
                result['start_time'] = dt

    if leading_date and 'start_time' not in result:
        dt = _parse_datetime(f"{leading_date} 18:00")
        if dt:
            result['start_time'] = dt

    return result





def _parse_score_style(line: str) -> Optional[Dict]:
    """Se skóre: Sparta - Slavia 2:1"""
    pattern = r'(.+?)\s+[-–]\s+(.+?)\s+(\d+)[:\-](\d+)'
    m = re.search(pattern, line)
    if not m:
        return None

    return {
        'home_team': m.group(1).strip(),
        'away_team': m.group(2).strip(),
        'home_score': int(m.group(3)),
        'away_score': int(m.group(4)),
    }




def _parse_vs_style(line: str) -> Optional[Dict]:
    """Vs style: Sparta vs Slavia"""
    pattern = r'(.+?)\s+(?:vs|versus)\s+(.+?)$'
    m = re.search(pattern, line, re.I)
    if not m:
        return None

    return {
        'home_team': m.group(1).strip(),
        'away_team': m.group(2).strip(),
    }




def _parse_dash_style(line: str) -> Optional[Dict]:
    """Dash style: Sparta - Slavia"""
    pattern = r'^(.+?)\s+[-–]\s+(.+?)$'
    m = re.search(pattern, line)
    if not m:
        return None

    return {
        'home_team': m.group(1).strip(),
        'away_team': m.group(2).strip(),
    }




def _parse_datetime(s: str) -> Optional[datetime]:
    """
    Parse datetime from string
    IMPROVED: Auto-fill missing year
    """
    s = s.strip()
    
    formats = [
        '%d. %m. %Y %H:%M',
        '%d. %m. %Y',
        '%d.%m.%Y %H:%M',
        '%d.%m.%Y',
        '%d/%m/%Y %H:%M',
        '%d/%m/%Y',
        '%Y-%m-%d %H:%M',
        '%Y-%m-%d',
        '%d. %m. %H:%M',
        '%d.%m. %H:%M',
        '%d. %m.',
        '%d.%m.',
    ]
    
    for fmt in formats:
        try:
            dt = datetime.strptime(s, fmt)
            # IMPROVEMENT: If year is missing (1900), add current/next year
            if dt.year == 1900:
                year = datetime.now().year
                if dt.month < datetime.now().month:
                    year += 1
                dt = dt.replace(year=year)
            return dt
        except:
            continue
    
    return None




def _is_date(text: str) -> bool:
    """Check if text looks like a date"""
    date_patterns = [
        r'^\d{1,2}\.\s*\d{1,2}\.\s*\d{4}$',  # 27. 2. 2026
        r'^\d{1,2}/\d{1,2}/\d{4}$',          # 27/2/2026
        r'^\d{4}-\d{1,2}-\d{1,2}$',          # 2026-2-27
        r'^\d{1,2}\.\s*\d{1,2}\.\s*$',       # 27. 2.
        r'^\d{1,2}\.\s*\d{1,2}\.$',          # 27.2.
    ]
    text = text.strip()
    for pattern in date_patterns:
        if re.match(pattern, text):
            return True
    return False




