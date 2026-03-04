"""
Scoring and Achievements Service
Handles point calculations, rankings, and achievements
"""

from models import db, User, Match, Tip, Round, Achievement, UserAchievement, ScoringHistory
from datetime import datetime
from sqlalchemy import func, desc


def check_and_award_achievements(user_id: int, round_id: int):
    """Zkontroluj a uděl achievementy pro uživatele v dané soutěži"""
    from flask import current_app

    user = db.session.get(User, user_id)
    r = db.session.get(Round, round_id)
    if not user or not r:
        return

    # Načti tipy uživatele
    my_tips = Tip.query.join(Match).filter(
        Tip.user_id == user_id,
        Match.round_id == round_id,
        Match.is_deleted == False
    ).all()

    if not my_tips:
        return

    # === FIRST TIP ===
    if len(my_tips) == 1:
        _award_achievement(user_id, 'first_tip', round_id)

    # Pro další achievementy potřebujeme vyhodnocené zápasy
    evaluated_tips = [t for t in my_tips if t.match.home_score is not None and t.match.away_score is not None]

    if not evaluated_tips:
        return

    # === HATTRICK & PERFECT 5 ===
    # Seřaď tipy podle data zápasu
    sorted_tips = sorted(evaluated_tips, key=lambda t: t.match.start_time or datetime.min)

    current_streak = 0
    max_streak = 0

    for tip in sorted_tips:
        points = calc_points_for_tip(tip.match, tip)
        if points == 3:  # Přesný tip
            current_streak += 1
            max_streak = max(max_streak, current_streak)
        else:
            current_streak = 0

    if max_streak >= 3:
        _award_achievement(user_id, 'hattrick', round_id)
    if max_streak >= 5:
        _award_achievement(user_id, 'perfect_5', round_id)
    if max_streak >= 10:
        _award_achievement(user_id, 'sniper', round_id)  # NOVÉ: 10 přesných po sobě!

    # === PERFECT ROUND ===
    # Zkontroluj jestli všechny tipy jsou přesné
    all_exact = all(calc_points_for_tip(t.match, t) == 3 for t in evaluated_tips)
    if all_exact and len(evaluated_tips) >= 3:  # Min 3 zápasy
        _award_achievement(user_id, 'perfect_round', round_id)

    # === FULL ATTENDANCE ===
    # Zkontroluj jestli tipoval všechny zápasy
    all_matches = Match.query.filter_by(round_id=round_id, is_deleted=False).all()
    tipped_match_ids = {t.match_id for t in my_tips}
    all_match_ids = {m.id for m in all_matches}

    if tipped_match_ids == all_match_ids and len(all_matches) >= 5:  # Min 5 zápasů
        _award_achievement(user_id, 'full_attendance', round_id)

    # === CENTURY & HALF CENTURY ===
    total_points = sum(calc_points_for_tip(t.match, t) for t in evaluated_tips)

    if total_points >= 50:
        _award_achievement(user_id, 'half_century', round_id)
    if total_points >= 100:
        _award_achievement(user_id, 'century', round_id)

    # === TOP TIPPER ===
    # Zkontroluj jestli má nejvíc bodů v soutěži
    all_users = User.query.all()
    user_scores = []

    for u in all_users:
        u_tips = Tip.query.join(Match).filter(
            Tip.user_id == u.id,
            Match.round_id == round_id,
            Match.is_deleted == False,
            Match.home_score != None,
            Match.away_score != None
        ).all()

        u_total = sum(calc_points_for_tip(t.match, t) for t in u_tips)
        user_scores.append({'user_id': u.id, 'total': u_total})

    user_scores.sort(key=lambda x: -x['total'])

    # Pokud je první (a má alespoň nějaké body)
    if user_scores and user_scores[0]['user_id'] == user_id and user_scores[0]['total'] > 0:
        # Zkontroluj že nemá stejný počet bodů s někým jiným
        top_score = user_scores[0]['total']
        top_count = sum(1 for x in user_scores if x['total'] == top_score)
        if top_count == 1:  # Jen on má nejvíc
            _award_achievement(user_id, 'top_tipper', round_id)

    # === WARRIOR ===
    # Účast ve 3+ soutěžích (global achievement)
    rounds_participated = db.session.query(Round.id).join(Match).join(Tip).filter(
        Tip.user_id == user_id,
        Match.is_deleted == False
    ).distinct().count()

    if rounds_participated >= 3:
        _award_achievement(user_id, 'warrior', None)  # Global, ne per-round

    # === UNDERDOG ===
    # Top 3 s méně než 50% tipnutých zápasů
    if len(user_scores) >= 3:
        top_3_users = [x['user_id'] for x in user_scores[:3]]
        if user_id in top_3_users:
            # Počet tipnutých vs všech zápasů
            total_matches_count = len(all_matches)
            tipped_count = len(my_tips)
            if total_matches_count > 0 and tipped_count / total_matches_count < 0.5:
                _award_achievement(user_id, 'underdog', round_id)



