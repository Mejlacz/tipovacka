"""
base_html.py
Centralni Jinja2 sablona pro celou aplikaci + render_page() helper.
Importuj takto:  from base_html import render_page
"""
from __future__ import annotations
from typing import Any, Dict, Optional

from flask import render_template_string
from flask_login import current_user
from flask_wtf.csrf import generate_csrf

from app_utils import get_rounds_for_switch, ensure_selected_round

BASE_HTML = r"""
<!doctype html>
<html lang="cs">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=5,user-scalable=yes">
  <meta name="csrf-token" content="{{ csrf_token() }}">
  <title>Tipovačka</title>
  
  <!-- PWA Meta Tags -->
  <meta name="description" content="Tipovací aplikace pro sázení na sportovní výsledky">
  <meta name="theme-color" content="#0b1020">
  <meta name="apple-mobile-web-app-capable" content="yes">
  <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
  <meta name="apple-mobile-web-app-title" content="Tipovačka">
  
  <!-- PWA Manifest -->
  <link rel="manifest" href="{{ url_for('pwa_manifest') }}">
  
  <!-- Icons -->
  <link rel="icon" type="image/png" sizes="192x192" href="{{ url_for('pwa_icon', size=192) }}">
  <link rel="icon" type="image/png" sizes="512x512" href="{{ url_for('pwa_icon', size=512) }}">
  <link rel="apple-touch-icon" href="{{ url_for('pwa_icon', size=192) }}">

  <style>
    /* ========================================
       COLOR THEMES - Default: Dark Blue
       ======================================== */
    
    :root{
      --bg:#0b1020; --card:#111a33; --text:#e9eefc; --muted:#a7b2d6;
      --line:rgba(255,255,255,.12); --accent:#6ea8fe;
      --ok:#33d17a; --warn:#f9c74f; --bad:#a7b2d6; --danger:#ff4d6d;
    }
    
    /* Light Theme */
    [data-theme="light"] {
      --bg:#f5f7fa; --card:#ffffff; --text:#1a1f2e; --muted:#6b7280;
      --line:rgba(0,0,0,.08); --accent:#3b82f6;
      --ok:#10b981; --warn:#f59e0b; --bad:#9ca3af; --danger:#ef4444;
    }
    
    [data-theme="light"] body {
      background: linear-gradient(180deg, #e5e7eb, #f5f7fa 35%, #f5f7fa);
    }
    
    [data-theme="light"] .card {
      background: #ffffff;
      box-shadow: 0 4px 20px rgba(0,0,0,.08);
    }
    
    [data-theme="light"] input, 
    [data-theme="light"] select, 
    [data-theme="light"] textarea {
      background: rgba(0,0,0,.03);
    }
    
    /* Green Theme */
    [data-theme="green"] {
      --bg:#0a1410; --card:#0f1f19; --text:#e8f5e9; --muted:#a5d6a7;
      --line:rgba(76,175,80,.15); --accent:#66bb6a;
      --ok:#81c784; --warn:#ffa726; --bad:#a5d6a7; --danger:#ef5350;
    }
    
    [data-theme="green"] body {
      background: linear-gradient(180deg, #051008, #0a1410 35%, #0a1410);
    }
    
    /* Purple Theme */
    [data-theme="purple"] {
      --bg:#1a0f1f; --card:#2a1a33; --text:#f3e5f5; --muted:#ce93d8;
      --line:rgba(186,104,200,.15); --accent:#ba68c8;
      --ok:#66bb6a; --warn:#ffb74d; --bad:#ce93d8; --danger:#ef5350;
    }
    
    [data-theme="purple"] body {
      background: linear-gradient(180deg, #0f0514, #1a0f1f 35%, #1a0f1f);
    }
    
    /* Ocean Theme */
    [data-theme="ocean"] {
      --bg:#051419; --card:#0a2533; --text:#e0f2f7; --muted:#80deea;
      --line:rgba(0,188,212,.15); --accent:#26c6da;
      --ok:#66bb6a; --warn:#ffca28; --bad:#80deea; --danger:#ff5252;
    }
    
    [data-theme="ocean"] body {
      background: linear-gradient(180deg, #020a0f, #051419 35%, #051419);
    }
    
    /* Sunset Theme */
    [data-theme="sunset"] {
      --bg:#1f0f0a; --card:#331a14; --text:#ffe8e0; --muted:#ffab91;
      --line:rgba(255,138,101,.15); --accent:#ff8a65;
      --ok:#66bb6a; --warn:#ffa726; --bad:#ffab91; --danger:#ef5350;
    }
    
    [data-theme="sunset"] body {
      background: linear-gradient(180deg, #140a05, #1f0f0a 35%, #1f0f0a);
    }
    
    /* Theme transition */
    body, .card, input, select, textarea {
      transition: background 0.3s ease, color 0.3s ease, border-color 0.3s ease;
    }
    
    /* ======================================== 
       VIZUÁLNÍ VYLEPŠENÍ & ANIMACE
       ======================================== */
    
    /* Smooth animations */
    @keyframes fadeIn {
      from { opacity: 0; transform: translateY(10px); }
      to { opacity: 1; transform: translateY(0); }
    }
    
    @keyframes slideIn {
      from { opacity: 0; transform: translateX(-20px); }
      to { opacity: 1; transform: translateX(0); }
    }
    
    @keyframes pulse {
      0%, 100% { transform: scale(1); }
      50% { transform: scale(1.05); }
    }
    
    /* Card animations */
    .card {
      animation: fadeIn 0.4s ease;
    }
    
    .card:hover {
      transform: translateY(-2px);
      box-shadow: 0 16px 40px rgba(0,0,0,.35);
      transition: transform 0.2s ease, box-shadow 0.3s ease;
    }
    
    /* Button effects */
    .btn {
      position: relative;
      overflow: hidden;
      transition: all 0.3s ease;
    }
    
    .btn::before {
      content: '';
      position: absolute;
      top: 50%;
      left: 50%;
      width: 0;
      height: 0;
      border-radius: 50%;
      background: rgba(255,255,255,.2);
      transform: translate(-50%, -50%);
      transition: width 0.4s, height 0.4s;
    }
    
    .btn:active::before {
      width: 300px;
      height: 300px;
    }
    
    .btn-primary {
      box-shadow: 0 4px 12px rgba(110,168,254,.25);
    }
    
    .btn-primary:hover {
      box-shadow: 0 6px 16px rgba(110,168,254,.35);
      transform: translateY(-1px);
    }
    
    /* Input focus effects */
    input:focus, select:focus, textarea:focus {
      border-color: var(--accent);
      box-shadow: 0 0 0 3px rgba(110,168,254,.1);
      transition: border-color 0.2s, box-shadow 0.2s;
    }
    
    /* Link hover effects */
    a {
      position: relative;
      transition: color 0.2s ease;
    }
    
    .nav a {
      position: relative;
      transition: all 0.2s ease;
    }
    
    .nav a::after {
      content: '';
      position: absolute;
      bottom: -2px;
      left: 0;
      width: 0;
      height: 2px;
      background: var(--accent);
      transition: width 0.3s ease;
    }
    
    .nav a:hover::after {
      width: 100%;
    }
    
    /* Tag animations */
    .tag {
      transition: all 0.2s ease;
    }
    
    .tag:hover {
      transform: scale(1.05);
    }
    
    /* Progress bar animation */
    @keyframes progressFill {
      from { width: 0; }
    }
    
    .progress-bar {
      animation: progressFill 1s ease-out;
    }
    
    /* Achievement card effects */
    .achievement-card {
      transition: all 0.3s ease;
    }
    
    .achievement-card:hover {
      transform: translateY(-4px) scale(1.02);
    }
    
    /* Stats card pulse on hover */
    .stat-card:hover {
      animation: pulse 0.6s ease;
    }
    
    /* Smooth scrolling */
    html {
      scroll-behavior: smooth;
    }
    
    /* Selection color */
    ::selection {
      background: var(--accent);
      color: #fff;
    }
    
    /* Custom scrollbar */
    ::-webkit-scrollbar {
      width: 10px;
      height: 10px;
    }
    
    ::-webkit-scrollbar-track {
      background: var(--card);
      border-radius: 10px;
    }
    
    ::-webkit-scrollbar-thumb {
      background: var(--accent);
      border-radius: 10px;
    }
    
    ::-webkit-scrollbar-thumb:hover {
      background: var(--accent);
      opacity: 0.8;
    }
    
    /* Loading animation */
    @keyframes spin {
      to { transform: rotate(360deg); }
    }
    
    .loading {
      animation: spin 1s linear infinite;
    }
    
    /* Notification badge pulse */
    .badge-pulse {
      animation: pulse 2s ease-in-out infinite;
    }
    
    /* Glassmorphism effect for cards */
    .card-glass {
      background: rgba(17,26,51,.65);
      backdrop-filter: blur(10px);
      -webkit-backdrop-filter: blur(10px);
    }
    
    /* Gradient text */
    .gradient-text {
      background: linear-gradient(135deg, var(--accent), var(--ok));
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
    }
    
    /* Shine effect on hover */
    @keyframes shine {
      to { background-position: 200% center; }
    }
    
    .shine:hover {
      background: linear-gradient(90deg, transparent, rgba(255,255,255,.1), transparent);
      background-size: 200% 100%;
      animation: shine 1.5s ease-in-out;
    }
    
    /* ======================================== */
    
    *{ box-sizing:border-box; }
    body{ margin:0; font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial;
          background:linear-gradient(180deg,#060a14,#0b1020 35%,#0b1020); color:var(--text); }
    a{ color:var(--accent); text-decoration:none; }
    a:hover{ text-decoration:underline; }

    .container{ max-width:1200px; margin:24px auto; padding:0 16px; }
    .topbar{ display:flex; align-items:center; justify-content:space-between; gap:12px; margin-bottom:16px; flex-wrap:wrap; }
    .brand{ font-weight:900; letter-spacing:.2px; }
    .nav a{ margin-left:10px; }
    
    /* Topbar actions container */
    .topbar-actions {
      display: flex;
      align-items: center;
      gap: 12px;
      flex-wrap: wrap;
    }
    
    /* Round selector */
    .round-selector {
      margin: 0;
    }
    
    .round-selector select {
      max-width: 200px;
    }

    .card{
      background:rgba(17,26,51,.85);
      border:1px solid var(--line);
      border-radius:14px;
      padding:14px;
      box-shadow:0 12px 30px rgba(0,0,0,.25);
    }
    .btn{
      display:inline-flex; align-items:center; justify-content:center;
      padding:9px 12px; border-radius:10px;
      border:1px solid var(--line);
      background:rgba(255,255,255,.06);
      color:var(--text);
      cursor:pointer;
    }
    .btn:hover{ background:rgba(255,255,255,.10); }
    .btn-primary{ background:rgba(110,168,254,.18); border-color:rgba(110,168,254,.5); }

    input, select, textarea{
      padding:9px 10px; border-radius:10px;
      border:1px solid var(--line);
      background:rgba(255,255,255,.05);
      color:var(--text);
      outline:none;
    }
    textarea{ min-height:160px; font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace; }
    select option{ color:#111; background:#fff; }

    .row{ display:flex; gap:10px; align-items:center; flex-wrap:wrap; }
    .sep{ border:none; border-top:1px solid var(--line); margin:14px 0; }

    .muted{ color:var(--muted); }
    .tag{ padding:2px 8px; border-radius:999px; border:1px solid var(--line); background:rgba(255,255,255,.05); font-size:12px; }
    .pill-ok{ color:var(--ok); border-color:rgba(51,209,122,.35); background:rgba(51,209,122,.10); }
    .pill-warn{ color:var(--warn); border-color:rgba(249,199,79,.35); background:rgba(249,199,79,.10); }
    .pill-bad{ color:var(--bad); border-color:rgba(167,178,214,.35); background:rgba(167,178,214,.07); }
    .score-final{ color:var(--danger); font-weight:900; }

    .grid2{ display:grid; grid-template-columns:1fr 1fr; gap:10px; }
    @media (max-width: 700px){ .grid2{ grid-template-columns:1fr; } }

    /* Mobilní vylepšení */
    @media (max-width: 768px) {
      .container { padding: 0 12px; margin: 12px auto; }
      .card { padding: 12px; }
      .lb-wrap { overflow-x: auto; -webkit-overflow-scrolling: touch; }
      .topbar { gap: 8px; flex-wrap: nowrap; }
      .topbar-actions { gap: 8px; }
      .round-selector select { max-width: 140px; font-size: 13px; padding: 6px 8px; }
      .theme-btn { padding: 6px 8px !important; font-size: 18px; }
      .nav a { margin-left: 6px; font-size: 14px; }
      .btn { padding: 8px 10px; font-size: 14px; }
      .btn-sm { padding: 6px 8px; font-size: 12px; }
      h2 { font-size: 20px; }
      h3 { font-size: 18px; }

      /* Zalamování řádku se zápasem na mobilu */
      .card .row[style*="flex-wrap:nowrap"] {
        flex-wrap: wrap !important;
      }
    }

    /* Touch-friendly vylepšení */
    @media (max-width: 768px) {
      /* Větší touch targety - minimálně 44x44px (Apple guidelines) */
      .btn, button, a.btn { 
        min-height: 44px;
        min-width: 44px;
        padding: 12px 20px; /* Větší padding pro pohodlné klikání */
      }
      
      /* Větší inputy pro snazší klikání */
      input, select, textarea {
        font-size: 16px; /* Zabrání auto-zoom na iOS */
        min-height: 44px;
        padding: 10px 12px;
      }
      
      /* Checkboxy a radio buttony větší */
      input[type="checkbox"],
      input[type="radio"] {
        min-width: 20px;
        min-height: 20px;
        width: 20px;
        height: 20px;
      }
      
      /* Horizontal scroll pro široké tabulky */
      /* DŮLEŽITÉ: Vynecháváme .lb (žebříček) protože má vlastní sticky columns! */
      .card {
        overflow-x: auto;
        -webkit-overflow-scrolling: touch; /* Smooth scroll na iOS */
      }
      
      /* Tabulky - horizontal scroll pokud jsou moc široké */
      /* VYLOUČENO: table.lb (žebříček má sticky columns a nesmí mít display:block) */
      table:not(.lb) {
        display: block;
        overflow-x: auto;
        -webkit-overflow-scrolling: touch;
        white-space: nowrap; /* Zabrání zalomení textu */
      }
      
      /* Datatable wrapper - ale NE žebříček! */
      .datatable:not(.lb) {
        display: block;
        overflow-x: auto;
        -webkit-overflow-scrolling: touch;
      }
      
      /* Card padding menší na mobilu */
      .card {
        padding: 16px;
        margin-bottom: 16px;
      }
      
      /* Větší řádkování pro lepší čitelnost */
      body {
        line-height: 1.6;
      }
      
      /* Tlačítka v řádku na mobilu - plná šířka nebo stack */
      .row {
        flex-direction: column;
        gap: 12px;
      }
      
      .row .btn {
        width: 100%; /* Plná šířka na mobilu */
      }
    }
    
    /* ═══════════════════════════════════════════════════
       DESKTOP NAVIGATION (default = 769px+)
       ═══════════════════════════════════════════════════ */
    /* Desktop nav visible by default */
    .desktop-nav {
      display: flex;
      align-items: center;
      gap: 4px;
    }
    
    .desktop-nav > a, .desktop-nav .nav-dropdown > a {
      padding: 8px 14px;
      border-radius: 8px;
      transition: background 0.2s;
      white-space: nowrap;
    }
    
    .desktop-nav > a:hover, .desktop-nav .nav-dropdown > a:hover {
      background: rgba(255,255,255,.08);
    }
    
    .desktop-nav .nav-dropdown {
      position: relative;
    }
    
    /* Dropdown hidden by default, shows on hover */
    .desktop-nav .nav-dropdown-menu {
      display: none;
      position: absolute;
      top: 100%;
      left: 0;
      min-width: 200px;
      background: rgba(11,16,32,0.98);
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: 6px;
      margin-top: 4px;
      box-shadow: 0 8px 24px rgba(0,0,0,.5);
      z-index: 1000;
    }
    
    .desktop-nav .nav-dropdown:hover .nav-dropdown-menu {
      display: block;
    }
    
    .desktop-nav .nav-dropdown-menu a {
      display: block;
      padding: 10px 14px;
      border-radius: 6px;
      transition: background 0.15s;
      white-space: nowrap;
    }
    
    .desktop-nav .nav-dropdown-menu a:hover {
      background: rgba(110,168,254,.15);
    }
    
    /* Mobile nav and hamburger hidden by default (desktop) */
    .mobile-nav {
      display: none;
    }
    
    .mobile-menu-btn {
      display: none;
    }
    
    /* ═══════════════════════════════════════════════════
       MOBILE NAVIGATION (max-width: 768px)
       ═══════════════════════════════════════════════════ */
    @media (max-width: 768px) {
        /* Hide desktop nav on mobile */
        .desktop-nav {
          display: none !important;
        }
        
        /* Show hamburger button */
        .mobile-menu-btn {
          display: block;
          background: rgba(255,255,255,.06);
          border: 1px solid var(--line);
          padding: 10px;
          border-radius: 10px;
          cursor: pointer;
          width: 44px;
          height: 44px;
        }
        
        .mobile-menu-btn span {
          display: block;
          width: 24px;
          height: 2px;
          background: var(--text);
          margin: 5px 0;
          transition: 0.3s;
        }
        
        /* Mobile nav - fullscreen overlay (hidden until toggled) */
        .mobile-nav {
          display: none;
          position: fixed;
          top: 0;
          left: 0;
          width: 100%;
          height: 100vh;
          background: rgba(11,16,32,0.98);
          z-index: 2000;
          flex-direction: column;
          justify-content: flex-start;
          padding-top: 80px;
          overflow-y: auto;
        }
        
        .mobile-nav.mobile-open {
          display: flex !important;
        }
        
        .mobile-nav > a, .mobile-nav .nav-dropdown > a {
          font-size: 18px;
          padding: 14px 20px;
          display: block;
          width: 85%;
          margin: 0 auto 8px auto;
          text-align: left;
          background: rgba(255,255,255,.05);
          border-radius: 10px;
        }
        
        .mobile-nav .nav-dropdown {
          width: 85%;
          margin: 0 auto 8px auto;
        }
        
        .mobile-nav .nav-dropdown > a {
          width: 100%;
          margin: 0;
          display: flex;
          justify-content: space-between;
          align-items: center;
        }
        
        .dropdown-arrow {
          font-size: 12px;
          transition: transform 0.2s;
        }
        
        .mobile-nav .nav-dropdown.open .dropdown-arrow {
          transform: rotate(180deg);
        }
        
        /* Mobile dropdown menu */
        .mobile-nav .nav-dropdown-menu {
          display: none;
          flex-direction: column;
          gap: 6px;
          padding: 8px 0 0 0;
        }
        
        .mobile-nav .nav-dropdown.open .nav-dropdown-menu {
          display: flex;
        }
        
        .mobile-nav .nav-dropdown-menu a {
          font-size: 16px !important;
          padding: 12px 20px !important;
          background: rgba(255,255,255,.03) !important;
          border-left: 3px solid rgba(110,168,254,.5);
          margin-left: 16px !important;
          width: calc(100% - 16px) !important;
        }
        
        /* Close button */
        .mobile-close-btn {
          position: fixed;
          top: 20px;
          right: 20px;
          font-size: 36px;
          background: rgba(255,255,255,.1);
          border: 1px solid var(--line);
          border-radius: 50%;
          color: var(--text);
          cursor: pointer;
          width: 50px;
          height: 50px;
          display: flex;
          align-items: center;
          justify-content: center;
          z-index: 2001;
        }
      }

    /* Datatable mobilní */
    @media (max-width: 768px) {
      .datatable { font-size: 13px; }
      .datatable th, .datatable td { padding: 8px 6px; }
    }
    
    /* PWA Install Banner */
    .pwa-install-banner {
      position: fixed;
      bottom: 0;
      left: 0;
      right: 0;
      background: linear-gradient(135deg, #6ea8fe, #5a8fd9);
      color: white;
      padding: 16px;
      display: none;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      z-index: 999;
      box-shadow: 0 -4px 20px rgba(0,0,0,.3);
    }
    
    .pwa-install-banner.show {
      display: flex;
    }
    
    .pwa-install-banner .btn {
      background: white;
      color: #0b1020;
      border: none;
      font-weight: 900;
    }
    
    .pwa-dismiss {
      background: transparent;
      border: 1px solid rgba(255,255,255,.5);
      color: white;
    }
    
    /* Theme Switcher */
    .theme-switcher {
      position: relative;
      display: inline-block;
    }
    
    .theme-btn {
      background: rgba(255,255,255,.06);
      border: 1px solid var(--line);
      padding: 8px 12px;
      border-radius: 10px;
      cursor: pointer;
      display: flex;
      align-items: center;
      gap: 6px;
      font-size: 14px;
      transition: background 0.2s;
    }
    
    .theme-btn:hover {
      background: rgba(255,255,255,.10);
    }
    
    .theme-dropdown {
      position: absolute;
      top: calc(100% + 8px);
      right: 0;
      background: var(--card);
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: 8px;
      min-width: 200px;
      box-shadow: 0 12px 30px rgba(0,0,0,.3);
      display: none;
      z-index: 100;
    }
    
    .theme-dropdown.show {
      display: block;
    }
    
    .theme-option {
      padding: 10px 12px;
      border-radius: 8px;
      cursor: pointer;
      display: flex;
      align-items: center;
      gap: 10px;
      transition: background 0.2s;
      margin-bottom: 4px;
    }
    
    .theme-option:hover {
      background: rgba(255,255,255,.08);
    }
    
    .theme-option.active {
      background: rgba(110,168,254,.18);
      border: 1px solid rgba(110,168,254,.5);
    }
    
    .theme-preview {
      width: 24px;
      height: 24px;
      border-radius: 6px;
      border: 1px solid var(--line);
    }
    
    .theme-preview.dark { background: linear-gradient(135deg, #0b1020, #6ea8fe); }
    .theme-preview.light { background: linear-gradient(135deg, #f5f7fa, #3b82f6); }
    .theme-preview.green { background: linear-gradient(135deg, #0a1410, #66bb6a); }
    .theme-preview.purple { background: linear-gradient(135deg, #1a0f1f, #ba68c8); }
    .theme-preview.ocean { background: linear-gradient(135deg, #051419, #26c6da); }
    .theme-preview.sunset { background: linear-gradient(135deg, #1f0f0a, #ff8a65); }
    
    @media (max-width: 768px) {
      .theme-switcher {
        position: static;
      }
      
      .theme-dropdown {
        position: fixed;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        right: auto;
      }
    }
    
    /* ========================================
       MOBILNÍ OPTIMALIZACE
       ======================================== */
    
    /* Větší touch targets pro mobil */
    @media (max-width: 768px) {
      /* Větší tlačítka */
      .btn {
        min-height: 44px;
        padding: 12px 20px;
        font-size: 16px;
      }
      
      .btn-sm {
        min-height: 40px;
        padding: 10px 16px;
        font-size: 14px;
      }
      
      /* Větší input fields */
      input[type="text"],
      input[type="email"],
      input[type="password"],
      input[type="number"],
      select,
      textarea {
        min-height: 44px;
        padding: 12px;
        font-size: 16px; /* Prevence auto-zoom na iOS */
      }
      
      /* Větší checkboxy */
      input[type="checkbox"] {
        width: 24px;
        height: 24px;
        min-width: 24px;
        min-height: 24px;
      }
      
      /* Responsive admin dashboard */
      .admin-dashboard {
        grid-template-columns: 1fr;
        gap: 12px;
      }
      
      .stat-card {
        padding: 16px;
      }
      
      .stat-value {
        font-size: 28px;
      }
      
      /* Bulk Edit table na mobilu */
      .bulk-table {
        font-size: 14px;
      }
      
      .bulk-table th,
      .bulk-table td {
        padding: 8px 4px;
      }
      
      .bulk-table input[type="number"] {
        width: 50px;
        min-height: 40px;
        font-size: 16px;
      }
      
      /* Undo tabulka */
      .datatable {
        font-size: 14px;
      }
      
      .datatable th,
      .datatable td {
        padding: 10px 8px;
      }
      
      /* Match preview (Smart Import) */
      .match-preview {
        flex-direction: column;
        align-items: flex-start;
        gap: 8px;
      }
      
      .match-checkbox {
        width: 24px;
        height: 24px;
      }
      
      /* Cards stack na mobilu */
      .row {
        flex-direction: column;
        gap: 12px;
      }
      
      .card {
        padding: 16px;
      }
      
      /* Zmenši navigaci */
      .topbar {
        padding: 12px 16px;
      }
      
      .brand {
        font-size: 18px;
      }
      
      /* Mobilní menu */
      .nav a {
        padding: 12px 16px;
        font-size: 16px;
      }
      
      /* Container */
      .container {
        padding: 12px;
      }
      
      /* Skryj méně důležité sloupce v tabulkách */
      .datatable th:nth-child(2),
      .datatable td:nth-child(2) {
        display: none;
      }
    }
    
    /* Extra malé obrazovky (< 480px) */
    @media (max-width: 480px) {
      .container {
        padding: 8px;
      }
      
      .card {
        padding: 12px;
        border-radius: 8px;
      }
      
      h1 { font-size: 24px; }
      h2 { font-size: 20px; }
      h3 { font-size: 18px; }
      
      /* Bulk Edit - scrollable horizontálně */
      .bulk-table-wrapper {
        overflow-x: auto;
        -webkit-overflow-scrolling: touch;
      }
      
      .bulk-table {
        min-width: 600px; /* Force scroll pokud je třeba */
      }
      
      /* Stack admin controls vertikálně */
      .admin-controls {
        flex-direction: column !important;
        align-items: stretch !important;
      }
      
      .admin-controls .btn {
        width: 100%;
      }
    }
    
    /* Touch-friendly hover effects */
    @media (hover: none) and (pointer: coarse) {
      /* Disable hover effects na touch zařízeních */
      .card:hover,
      .stat-card:hover,
      .match-row:hover {
        transform: none;
      }
      
      /* Ale přidej active state */
      .btn:active {
        transform: scale(0.97);
        opacity: 0.9;
      }
      
      .card:active {
        background: rgba(255,255,255,.05);
      }
    }
    
    /* Landscape orientation optimalizace */
    @media (max-width: 768px) and (orientation: landscape) {
      .container {
        padding: 8px 16px;
      }
      
      .stat-card {
        padding: 12px;
      }
      
      .stat-value {
        font-size: 24px;
      }
    }
    
    /* Bottom Navigation (pouze mobil) */
    .bottom-nav {
      display: none;
      position: fixed;
      bottom: 0;
      left: 0;
      right: 0;
      background: var(--card);
      border-top: 1px solid var(--line);
      padding: 8px 0;
      z-index: 1000;
      box-shadow: 0 -2px 10px rgba(0,0,0,.1);
    }
    
    @media (max-width: 768px) {
      .bottom-nav {
        display: flex;
        justify-content: space-around;
        align-items: center;
      }
      
      /* Přidej padding na konci stránky kvůli bottom nav */
      .container {
        padding-bottom: 80px;
      }
    }
    
    .bottom-nav-item {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      text-decoration: none;
      color: var(--muted);
      font-size: 11px;
      padding: 8px 12px;
      border-radius: 8px;
      transition: all 0.2s ease;
      min-width: 60px;
    }
    
    .bottom-nav-item:hover,
    .bottom-nav-item.active {
      color: var(--accent);
      background: rgba(110,168,254,.1);
    }
    
    .bottom-nav-item .nav-icon {
      font-size: 24px;
      margin-bottom: 4px;
    }
    
    /* iOS Safe Area */
    @supports (padding: max(0px)) {
      body {
        padding-left: max(0px, env(safe-area-inset-left));
        padding-right: max(0px, env(safe-area-inset-right));
      }
      
      .topbar {
        padding-top: max(12px, env(safe-area-inset-top));
      }
      
      .bottom-nav {
        padding-bottom: max(8px, env(safe-area-inset-bottom));
      }
    }
    
    /* Swipe gestures hint */
    @media (max-width: 768px) {
      .swipeable {
        touch-action: pan-y;
        position: relative;
      }
      
      .swipeable::after {
        content: '';
        position: absolute;
        left: 0;
        top: 50%;
        transform: translateY(-50%);
        width: 4px;
        height: 40%;
        background: var(--accent);
        opacity: 0.3;
        border-radius: 0 4px 4px 0;
      }
    }
  

    /* ========================================
       TABLE LAYOUT IMPROVEMENTS (Smart Import Preview + Admin tables)
       ======================================== */
    table.preview-table{ width:100%; border-collapse:separate; border-spacing:0; table-layout:fixed; }
    table.preview-table thead th{ position:sticky; top:0; z-index:2; background:var(--card); }
    table.preview-table th, table.preview-table td{ padding:10px 8px; vertical-align:middle; }
    table.preview-table td:first-child, table.preview-table th:first-child{ text-align:center; }
    table.preview-table input[type="text"]{ width:100%; min-width:120px; }
    table.preview-table input.home-score, 
    table.preview-table input.away-score, 
    table.preview-table input[type="number"].home-score,
    table.preview-table input[type="number"].away-score{ width:70px; text-align:center; }
    table.preview-table input.start-time{ width:180px; max-width:100%; }
    @media (max-width: 900px){
      table.preview-table{ table-layout:auto; }
      table.preview-table input.start-time{ width:160px; }
    }

</style>
</head>

<body>
  <div class="container">
    <div class="topbar">
      <div class="brand">Tipovačka</div>

      <div class="topbar-actions">
        {% if current_user.is_authenticated %}
          {% if rounds_for_switch and selected_round_id_for_switch %}
            <form method="post" action="{{ url_for('set_round') }}" class="round-selector">
              <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
              <input type="hidden" name="next" value="{{ request.full_path }}">
              <select name="round_id" onchange="this.form.submit()">
                {% for r in rounds_for_switch %}
                  <option value="{{ r.id }}" {% if r.id == selected_round_id_for_switch %}selected{% endif %}>
                    {% if r.is_active %}★ {% endif %}{{ r.name }}
                  </option>
                {% endfor %}
              </select>
            </form>
          {% endif %}

          <!-- Theme Switcher -->
          <div class="theme-switcher">
            <button class="theme-btn" onclick="toggleThemeDropdown()" aria-label="Změnit motiv">
              🎨
            </button>
            <div class="theme-dropdown" id="theme-dropdown">
              <div class="theme-option active" data-theme="dark" onclick="setTheme('dark')">
                <div class="theme-preview dark"></div>
                <span>Dark Blue (výchozí)</span>
              </div>
              <div class="theme-option" data-theme="light" onclick="setTheme('light')">
                <div class="theme-preview light"></div>
                <span>Light</span>
              </div>
              <div class="theme-option" data-theme="green" onclick="setTheme('green')">
                <div class="theme-preview green"></div>
                <span>Green Forest</span>
              </div>
              <div class="theme-option" data-theme="purple" onclick="setTheme('purple')">
                <div class="theme-preview purple"></div>
                <span>Purple Night</span>
              </div>
              <div class="theme-option" data-theme="ocean" onclick="setTheme('ocean')">
                <div class="theme-preview ocean"></div>
                <span>Ocean Blue</span>
              </div>
              <div class="theme-option" data-theme="sunset" onclick="setTheme('sunset')">
                <div class="theme-preview sunset"></div>
                <span>Sunset Orange</span>
              </div>
            </div>
          </div>

          <!-- Mobile menu button -->
          <button class="mobile-menu-btn" onclick="toggleMobileMenu()" aria-label="Menu">
            <span></span>
            <span></span>
            <span></span>
          </button>

          <!-- DESKTOP NAVIGATION -->
          <div class="nav desktop-nav">
            <a href="{{ url_for('home') }}">🏠 Home</a>
            
            <div class="nav-dropdown">
              <a href="{{ url_for('leaderboard') }}">📊 Žebříček</a>
              <div class="nav-dropdown-menu">
                <a href="{{ url_for('leaderboard') }}">Hlavní žebříček</a>
                <a href="{{ url_for('mini_leaderboards') }}">Mini žebříčky</a>
                <a href="{{ url_for('compare') }}">Porovnat</a>
              </div>
            </div>
            
            <div class="nav-dropdown">
              <a href="{{ url_for('matches') }}">⚽ Zápasy</a>
              <div class="nav-dropdown-menu">
                <a href="{{ url_for('matches') }}">Všechny zápasy</a>
                <a href="{{ url_for('teams') }}">Týmy</a>
              </div>
            </div>
            
            <a href="{{ url_for('extras') }}">🎯 Extra</a>
            <a href="{{ url_for('archive') }}">📦 Archiv</a>
            
            <div class="nav-dropdown">
              <a href="{{ url_for('my_stats') }}">📈 Stats</a>
              <div class="nav-dropdown-menu">
                <a href="{{ url_for('my_stats') }}">Moje statistiky</a>
                <a href="{{ url_for('achievements') }}">Achievementy</a>
              </div>
            </div>
            
            {% if current_user.is_admin_effective %}
              <div class="nav-dropdown">
                <a href="{{ url_for('admin_dashboard') }}">⚙️ Admin</a>
                <div class="nav-dropdown-menu">
                  <a href="{{ url_for('admin_dashboard') }}">Dashboard</a>
                  <a href="{{ url_for('admin_rounds') }}">Soutěže</a>
                  <a href="{{ url_for('admin_import') }}">Import</a>
                  <a href="{{ url_for('admin_export_hub') }}">Export</a>
                  <a href="{{ url_for('admin_bulk_edit') }}">Bulk Edit</a>
                  <a href="{{ url_for('admin_undo') }}">Undo</a>
                  <a href="{{ url_for('admin_users') }}">Uživatelé</a>
                  <a href="{{ url_for('admin_api_sources') }}">🔌 API Zdroje</a>
                  <a href="{{ url_for('admin_team_aliases') }}">🔁 Aliasy týmů</a>
                  <a href="{{ url_for('admin_backup') }}">💾 Záloha</a>
                  <a href="{{ url_for('admin_audit') }}">Historie</a>
                </div>
              </div>
            {% endif %}
            
            <div class="nav-dropdown">
              <a href="#">👤 {{ current_user.display_name }}</a>
              <div class="nav-dropdown-menu">
                <a href="{{ url_for('change_password') }}">Změnit heslo</a>
                <a href="{{ url_for('logout') }}">Odhlásit</a>
              </div>
            </div>
          </div>
          
          <!-- MOBILE NAVIGATION -->
          <div class="nav mobile-nav" id="mobile-nav">
            <button class="mobile-close-btn" onclick="toggleMobileMenu()">×</button>
            
            <a href="{{ url_for('home') }}" onclick="closeMobileMenu()">🏠 Home</a>
            
            <div class="nav-dropdown">
              <a href="#" class="nav-dropdown-toggle" onclick="toggleDropdown(event)">
                📊 Žebříček <span class="dropdown-arrow">▼</span>
              </a>
              <div class="nav-dropdown-menu">
                <a href="{{ url_for('leaderboard') }}" onclick="closeMobileMenu()">Hlavní žebříček</a>
                <a href="{{ url_for('mini_leaderboards') }}" onclick="closeMobileMenu()">Mini žebříčky</a>
                <a href="{{ url_for('compare') }}" onclick="closeMobileMenu()">Porovnat</a>
              </div>
            </div>
            
            <div class="nav-dropdown">
              <a href="#" class="nav-dropdown-toggle" onclick="toggleDropdown(event)">
                ⚽ Zápasy <span class="dropdown-arrow">▼</span>
              </a>
              <div class="nav-dropdown-menu">
                <a href="{{ url_for('matches') }}" onclick="closeMobileMenu()">Všechny zápasy</a>
                <a href="{{ url_for('teams') }}" onclick="closeMobileMenu()">Týmy</a>
              </div>
            </div>
            
            <a href="{{ url_for('extras') }}" onclick="closeMobileMenu()">🎯 Extra</a>
            <a href="{{ url_for('archive') }}" onclick="closeMobileMenu()">📦 Archiv</a>
            
            <div class="nav-dropdown">
              <a href="#" class="nav-dropdown-toggle" onclick="toggleDropdown(event)">
                📈 Stats <span class="dropdown-arrow">▼</span>
              </a>
              <div class="nav-dropdown-menu">
                <a href="{{ url_for('my_stats') }}" onclick="closeMobileMenu()">Moje statistiky</a>
                <a href="{{ url_for('achievements') }}" onclick="closeMobileMenu()">Achievementy</a>
              </div>
            </div>
            
            {% if current_user.is_admin_effective %}
              <div class="nav-dropdown">
                <a href="#" class="nav-dropdown-toggle" onclick="toggleDropdown(event)">
                  ⚙️ Admin <span class="dropdown-arrow">▼</span>
                </a>
                <div class="nav-dropdown-menu">
                  <a href="{{ url_for('admin_dashboard') }}" onclick="closeMobileMenu()">Dashboard</a>
                  <a href="{{ url_for('admin_rounds') }}" onclick="closeMobileMenu()">Soutěže</a>
                  <a href="{{ url_for('admin_import') }}" onclick="closeMobileMenu()">Import</a>
                  <a href="{{ url_for('admin_export_hub') }}" onclick="closeMobileMenu()">Export</a>
                  <a href="{{ url_for('admin_bulk_edit') }}" onclick="closeMobileMenu()">Bulk Edit</a>
                  <a href="{{ url_for('admin_undo') }}" onclick="closeMobileMenu()">Undo</a>
                  <a href="{{ url_for('admin_users') }}" onclick="closeMobileMenu()">Uživatelé</a>
                  <a href="{{ url_for('admin_api_sources') }}" onclick="closeMobileMenu()">🔌 API Zdroje</a>
                  <a href="{{ url_for('admin_backup') }}" onclick="closeMobileMenu()">💾 Záloha</a>
                  <a href="{{ url_for('admin_audit') }}" onclick="closeMobileMenu()">Historie</a>
                </div>
              </div>
            {% endif %}
            
            <div class="nav-dropdown">
              <a href="#" class="nav-dropdown-toggle" onclick="toggleDropdown(event)">
                👤 {{ current_user.display_name }} <span class="dropdown-arrow">▼</span>
              </a>
              <div class="nav-dropdown-menu">
                <a href="{{ url_for('change_password') }}" onclick="closeMobileMenu()">Změnit heslo</a>
                <a href="{{ url_for('logout') }}" onclick="closeMobileMenu()">Odhlásit</a>
              </div>
            </div>
          </div>
        {% else %}
          <div class="nav">
            <a href="{{ url_for('login') }}">Login</a>
            <a href="{{ url_for('register') }}">Registrace</a>
          </div>
        {% endif %}
      </div>
    </div>

    {% with messages = get_flashed_messages(with_categories=true) %}
      {% if messages %}
        <div class="card" style="margin-bottom:14px;">
          {% for cat, msg in messages %}
            <div style="margin:6px 0;">
              <span class="tag">{{ cat }}</span>
              <span style="margin-left:8px;">{{ msg }}</span>
            </div>
          {% endfor %}
        </div>
      {% endif %}
    {% endwith %}

    {{ content|safe }}
  </div>
  
  <!-- PWA Install Banner -->
  <div class="pwa-install-banner" id="pwa-banner">
    <div>
      <strong>📱 Instaluj aplikaci</strong>
      <div style="font-size: 13px; opacity: 0.9; margin-top: 4px;">
        Přidej si Tipovačku na plochu!
      </div>
    </div>
    <div style="display: flex; gap: 8px;">
      <button class="btn" onclick="installPWA()">Instalovat</button>
      <button class="btn pwa-dismiss" onclick="dismissPWA()">Později</button>
    </div>
  </div>
  
  <script>
    // Mobile menu toggle
    function toggleMobileMenu() {
      const nav = document.getElementById('mobile-nav');
      nav.classList.toggle('mobile-open');
    }
    
    function closeMobileMenu() {
      const nav = document.getElementById('mobile-nav');
      nav.classList.remove('mobile-open');
      // Zavři všechny dropdowny
      document.querySelectorAll('.mobile-nav .nav-dropdown').forEach(d => d.classList.remove('open'));
    }
    
    // Mobile dropdown toggle
    function toggleDropdown(e) {
      e.preventDefault();
      e.stopPropagation();
      
      const toggle = e.currentTarget;
      const dropdown = toggle.parentElement;
      const isOpen = dropdown.classList.contains('open');
      
      // Zavři ostatní dropdowny
      document.querySelectorAll('.mobile-nav .nav-dropdown').forEach(d => {
        if (d !== dropdown) d.classList.remove('open');
      });
      
      // Toggle aktuální
      dropdown.classList.toggle('open');
    }
    
    // PWA Install
    let deferredPrompt;
    
    window.addEventListener('beforeinstallprompt', (e) => {
      e.preventDefault();
      deferredPrompt = e;
      
      // Zobraz banner pokud už nebyl dismissed
      if (!localStorage.getItem('pwa-dismissed')) {
        document.getElementById('pwa-banner').classList.add('show');
      }
    });
    
    function installPWA() {
      if (deferredPrompt) {
        deferredPrompt.prompt();
        deferredPrompt.userChoice.then((choiceResult) => {
          if (choiceResult.outcome === 'accepted') {
            console.log('PWA installed');
          }
          deferredPrompt = null;
          document.getElementById('pwa-banner').classList.remove('show');
        });
      }
    }
    
    function dismissPWA() {
      document.getElementById('pwa-banner').classList.remove('show');
      localStorage.setItem('pwa-dismissed', 'true');
    }
    
    // Theme Switcher
    const themes = {
      'dark': 'Dark Blue',
      'light': 'Light',
      'green': 'Green Forest',
      'purple': 'Purple Night',
      'ocean': 'Ocean Blue',
      'sunset': 'Sunset Orange'
    };
    
    function toggleThemeDropdown() {
      const dropdown = document.getElementById('theme-dropdown');
      dropdown.classList.toggle('show');
      
      // Zavři při kliknutí mimo
      if (dropdown.classList.contains('show')) {
        setTimeout(() => {
          document.addEventListener('click', closeThemeOnClickOutside);
        }, 0);
      }
    }
    
    function closeThemeOnClickOutside(e) {
      const dropdown = document.getElementById('theme-dropdown');
      const themeSwitcher = dropdown.closest('.theme-switcher');
      
      if (!themeSwitcher.contains(e.target)) {
        dropdown.classList.remove('show');
        document.removeEventListener('click', closeThemeOnClickOutside);
      }
    }
    
    function setTheme(theme) {
      // Nastav data-theme na html element
      document.documentElement.setAttribute('data-theme', theme);
      
      // Ulož do localStorage
      localStorage.setItem('preferred-theme', theme);
      
      // Označ že je to manuální override (ne auto)
      localStorage.setItem('theme-manual-override', 'true');
      
      // Update UI
      updateThemeUI(theme);
      
      // Zavři dropdown
      document.getElementById('theme-dropdown').classList.remove('show');
      document.removeEventListener('click', closeThemeOnClickOutside);
    }
    
    function updateThemeUI(theme) {
      // Update button text
      document.getElementById('current-theme-name').textContent = themes[theme] || 'Dark';
      
      // Update active option
      document.querySelectorAll('.theme-option').forEach(option => {
        if (option.dataset.theme === theme) {
          option.classList.add('active');
        } else {
          option.classList.remove('active');
        }
      });
    }
    
    // Auto Dark/Light Theme Detection
    function detectAutoTheme() {
      // 1. Pokud má uživatel manuální override, použij to
      const manualTheme = localStorage.getItem('preferred-theme');
      const isManualOverride = localStorage.getItem('theme-manual-override') === 'true';
      
      if (isManualOverride && manualTheme) {
        return manualTheme;
      }
      
      // 2. Detekce system preference (Dark Mode v OS)
      if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
        return 'dark';
      }
      
      if (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) {
        return 'light';
      }
      
      // 3. Auto-switch podle času (18:00-6:00 = dark)
      const hour = new Date().getHours();
      if (hour >= 18 || hour < 6) {
        return 'dark'; // Večer/noc
      } else {
        return 'light'; // Den
      }
    }
    
    // Načti saved theme při startu
    window.addEventListener('DOMContentLoaded', () => {
      const autoTheme = detectAutoTheme();
      document.documentElement.setAttribute('data-theme', autoTheme);
      
      // Update UI pokud existuje
      const themeNameEl = document.getElementById('current-theme-name');
      if (themeNameEl) {
        updateThemeUI(autoTheme);
      }
      
      // Poslouchej system preference změny
      if (window.matchMedia) {
        const darkModeQuery = window.matchMedia('(prefers-color-scheme: dark)');
        darkModeQuery.addEventListener('change', (e) => {
          // Pokud není manual override, auto-přepni
          const isManual = localStorage.getItem('theme-manual-override') === 'true';
          if (!isManual) {
            const newTheme = e.matches ? 'dark' : 'light';
            document.documentElement.setAttribute('data-theme', newTheme);
            if (themeNameEl) {
              updateThemeUI(newTheme);
            }
          }
        });
      }
    });
    
    // Keyboard Shortcuts pro adminy
    {% if current_user.is_authenticated and current_user.is_admin_effective %}
    document.addEventListener('keydown', function(e) {
      // Ctrl/Cmd + Shift + D = Dashboard
      if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key === 'D') {
        e.preventDefault();
        window.location.href = "{{ url_for('admin_dashboard') }}";
      }
      
      // Ctrl/Cmd + Shift + B = Bulk Edit
      if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key === 'B') {
        e.preventDefault();
        window.location.href = "{{ url_for('admin_bulk_edit') }}";
      }
    });
    {% endif %}
    
    // Service Worker registrace
    if ('serviceWorker' in navigator) {
      window.addEventListener('load', () => {
        navigator.serviceWorker.register('/service-worker.js')
          .then(reg => console.log('Service Worker registered'))
          .catch(err => console.log('Service Worker registration failed:', err));
      });
    }
  </script>
  
  {% if current_user.is_authenticated %}
  <!-- Bottom Navigation (mobil - pro všechny) -->
  <nav class="bottom-nav">
    {% if current_user.is_admin_effective %}
      <!-- Admin verze -->
      <a href="{{ url_for('admin_dashboard') }}" class="bottom-nav-item {% if request.endpoint == 'admin_dashboard' %}active{% endif %}">
        <div class="nav-icon">👨‍💼</div>
        <div>Dashboard</div>
      </a>
      <a href="{{ url_for('admin_bulk_edit') }}" class="bottom-nav-item {% if request.endpoint == 'admin_bulk_edit' %}active{% endif %}">
        <div class="nav-icon">✏️</div>
        <div>Bulk Edit</div>
      </a>
      <a href="{{ url_for('admin_undo') }}" class="bottom-nav-item {% if request.endpoint == 'admin_undo' %}active{% endif %}">
        <div class="nav-icon">🔄</div>
        <div>Undo</div>
      </a>
      <a href="{{ url_for('admin_import') }}" class="bottom-nav-item {% if request.endpoint == 'admin_import' %}active{% endif %}">
        <div class="nav-icon">📥</div>
        <div>Import</div>
      </a>
    {% else %}
      <!-- User verze -->
      <a href="{{ url_for('leaderboard') }}" class="bottom-nav-item {% if request.endpoint == 'leaderboard' %}active{% endif %}">
        <div class="nav-icon">🏆</div>
        <div>Žebříček</div>
      </a>
      <a href="{{ url_for('my_tips') }}" class="bottom-nav-item {% if request.endpoint == 'my_tips' %}active{% endif %}">
        <div class="nav-icon">🎯</div>
        <div>Tipy</div>
      </a>
      <a href="{{ url_for('profile') }}" class="bottom-nav-item {% if request.endpoint == 'profile' %}active{% endif %}">
        <div class="nav-icon">👤</div>
        <div>Profil</div>
      </a>
      <a href="{{ url_for('archive') }}" class="bottom-nav-item {% if request.endpoint == 'archive' %}active{% endif %}">
        <div class="nav-icon">📚</div>
        <div>Archiv</div>
      </a>
    {% endif %}
  </nav>
  {% endif %}
  
  <!-- Push Notification Button (floating) -->
  {% if current_user.is_authenticated %}
  <button id="push-notification-btn" class="push-notif-btn" draggable="true" style="display:none;" title="Notifikace (přesouvatelné)">
    <span id="push-icon">🔔</span>
  </button>
  {% endif %}
  
  <style>
    /* Floating Notification Button */
    .push-notif-btn {
      position: fixed !important;  /* Force fixed */
      top: 80px;
      right: 20px;
      width: 50px;
      height: 50px;
      border-radius: 50%;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      border: none;
      box-shadow: 0 4px 12px rgba(0,0,0,0.3);
      cursor: move;  /* Změněno z pointer na move */
      z-index: 99999 !important;  /* Nad vším! */
      font-size: 24px;
      transition: transform 0.3s ease, box-shadow 0.3s ease;  /* Bez transition na top/left */
      display: flex;
      align-items: center;
      justify-content: center;
      user-select: none;
      touch-action: none;
    }
    
    .push-notif-btn:hover {
      transform: scale(1.1);
      box-shadow: 0 6px 16px rgba(0,0,0,0.4);
    }
    
    .push-notif-btn:active {
      transform: scale(0.95);
    }
    
    .push-notif-btn.dragging {
      opacity: 0.8;
      transform: scale(1.15);
      cursor: grabbing;
    }
    
    .push-notif-btn.disabled {
      background: linear-gradient(135deg, #6b7280 0%, #4b5563 100%);
      opacity: 0.6;
    }
    
    @media (max-width: 768px) {
      .push-notif-btn {
        top: 16px;        /* Výš aby nebyl zakrytý */
        right: 16px;
        width: 48px;      /* Trochu větší pro touch */
        height: 48px;
        font-size: 22px;
        z-index: 99999 !important;  /* Opakuji pro jistotu */
      }
    }
  </style>
  
  <script>
    // Push Notification Management
    {% if current_user.is_authenticated %}
    (function() {
      const btn = document.getElementById('push-notification-btn');
      const icon = document.getElementById('push-icon');
      
      if (!btn) return;
      
      // Check if push is supported
      if (!('serviceWorker' in navigator) || !('PushManager' in window)) {
        console.log('Push notifications not supported');
        return;
      }
      
      // Show button
      btn.style.display = 'flex';
      
      // Check current subscription status
      navigator.serviceWorker.ready.then(registration => {
        return registration.pushManager.getSubscription();
      }).then(subscription => {
        updateUI(!!subscription);
      });
      
      // Button click handler with long press for settings
      let pressTimer;
      
      btn.addEventListener('mousedown', () => {
        pressTimer = setTimeout(() => {
          // Long press - open settings
          window.location.href = '/notification-settings';
        }, 500);  // 500ms = long press
      });
      
      btn.addEventListener('mouseup', () => {
        clearTimeout(pressTimer);
      });
      
      btn.addEventListener('touchstart', () => {
        pressTimer = setTimeout(() => {
          // Long press - open settings
          window.location.href = '/notification-settings';
        }, 500);
      });
      
      btn.addEventListener('touchend', () => {
        clearTimeout(pressTimer);
      });
      
      btn.addEventListener('click', async () => {
        try {
          const registration = await navigator.serviceWorker.ready;
          const subscription = await registration.pushManager.getSubscription();
          
          if (subscription) {
            // Unsubscribe
            await unsubscribeUser(subscription);
          } else {
            // Subscribe
            await subscribeUser(registration);
          }
        } catch (error) {
          console.error('Push error:', error);
          alert('Chyba: ' + error.message);
        }
      });
      
      async function subscribeUser(registration) {
        try {
          // Request permission
          const permission = await Notification.requestPermission();
          
          if (permission !== 'granted') {
            alert('❌ Notifikace nejsou povolené v prohlížeči');
            return;
          }
          
          // Get public key
          const response = await fetch('/api/push/vapid-public-key');
          const data = await response.json();
          const publicKey = data.publicKey;
          
          // Subscribe
          const subscription = await registration.pushManager.subscribe({
            userVisibleOnly: true,
            applicationServerKey: urlBase64ToUint8Array(publicKey)
          });
          
          // Send to server
          const subResponse = await fetchWithCSRF('/api/push/subscribe', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json'
            },
            body: JSON.stringify(subscription.toJSON())
          });
          
          const result = await subResponse.json();
          
          if (result.success) {
            updateUI(true);
            showToast('✅ Notifikace povoleny!');
          } else {
            throw new Error(result.message);
          }
          
        } catch (error) {
          console.error('Subscribe error:', error);
          alert('Chyba při povolování notifikací: ' + error.message);
        }
      }
      
      async function unsubscribeUser(subscription) {
        try {
          // Unsubscribe from push service
          await subscription.unsubscribe();
          
          // Tell server
          await fetchWithCSRF('/api/push/unsubscribe', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json'
            },
            body: JSON.stringify(subscription.toJSON())
          });
          
          updateUI(false);
          showToast('🔕 Notifikace zakázány');
          
        } catch (error) {
          console.error('Unsubscribe error:', error);
          alert('Chyba při zakazování notifikací: ' + error.message);
        }
      }
      
      function updateUI(isSubscribed) {
        if (isSubscribed) {
          icon.textContent = '🔔';
          btn.classList.remove('disabled');
          btn.title = 'Zakázat notifikace';
        } else {
          icon.textContent = '🔕';
          btn.classList.add('disabled');
          btn.title = 'Povolit notifikace';
        }
      }
      
      function showToast(message) {
        // Simple toast notification
        const toast = document.createElement('div');
        toast.textContent = message;
        toast.style.cssText = `
          position: fixed;
          top: 140px;
          right: 20px;
          background: rgba(17,26,51,0.95);
          color: #e9eefc;
          padding: 12px 20px;
          border-radius: 8px;
          box-shadow: 0 4px 12px rgba(0,0,0,0.3);
          z-index: 10000;
          font-size: 14px;
          animation: slideIn 0.3s ease;
        `;
        document.body.appendChild(toast);
        
        setTimeout(() => {
          toast.style.animation = 'slideOut 0.3s ease';
          setTimeout(() => toast.remove(), 300);
        }, 3000);
      }
      
      function urlBase64ToUint8Array(base64String) {
        const padding = '='.repeat((4 - base64String.length % 4) % 4);
        const base64 = (base64String + padding)
          .replace(/\-/g, '+')
          .replace(/_/g, '/');
        
        const rawData = window.atob(base64);
        const outputArray = new Uint8Array(rawData.length);
        
        for (let i = 0; i < rawData.length; ++i) {
          outputArray[i] = rawData.charCodeAt(i);
        }
        return outputArray;
      }
      
      // ========== DRAG & DROP FUNCTIONALITY ==========
      let isDragging = false;
      let dragStartX, dragStartY;
      let btnStartX, btnStartY;
      
      // Load saved position from localStorage
      function loadPosition() {
        const saved = localStorage.getItem('push-btn-position');
        if (saved) {
          try {
            const pos = JSON.parse(saved);
            btn.style.left = pos.x + 'px';
            btn.style.top = pos.y + 'px';
            btn.style.right = 'auto';  // Disable right positioning
          } catch (e) {
            console.error('Error loading button position:', e);
          }
        }
      }
      
      // Save position to localStorage
      function savePosition() {
        const rect = btn.getBoundingClientRect();
        localStorage.setItem('push-btn-position', JSON.stringify({
          x: rect.left,
          y: rect.top
        }));
      }
      
      // Mouse/Touch drag handlers
      function startDrag(e) {
        isDragging = true;
        btn.classList.add('dragging');
        
        const touch = e.type.includes('touch') ? e.touches[0] : e;
        dragStartX = touch.clientX;
        dragStartY = touch.clientY;
        
        const rect = btn.getBoundingClientRect();
        btnStartX = rect.left;
        btnStartY = rect.top;
        
        // Prevent default to avoid text selection
        e.preventDefault();
      }
      
      function doDrag(e) {
        if (!isDragging) return;
        
        const touch = e.type.includes('touch') ? e.touches[0] : e;
        const deltaX = touch.clientX - dragStartX;
        const deltaY = touch.clientY - dragStartY;
        
        const newX = btnStartX + deltaX;
        const newY = btnStartY + deltaY;
        
        // Keep button within viewport
        const maxX = window.innerWidth - btn.offsetWidth;
        const maxY = window.innerHeight - btn.offsetHeight;
        
        btn.style.left = Math.max(0, Math.min(newX, maxX)) + 'px';
        btn.style.top = Math.max(0, Math.min(newY, maxY)) + 'px';
        btn.style.right = 'auto';  // Disable right positioning
        
        e.preventDefault();
      }
      
      function endDrag(e) {
        if (!isDragging) return;
        
        isDragging = false;
        btn.classList.remove('dragging');
        savePosition();
        
        e.preventDefault();
        
        // Prevent click event if dragged more than 5px
        const touch = e.type.includes('touch') ? e.changedTouches[0] : e;
        const moved = Math.abs(touch.clientX - dragStartX) + Math.abs(touch.clientY - dragStartY);
        if (moved > 5) {
          e.stopPropagation();
        }
      }
      
      // Add event listeners for drag
      btn.addEventListener('mousedown', startDrag);
      document.addEventListener('mousemove', doDrag);
      document.addEventListener('mouseup', endDrag);
      
      // Touch events for mobile
      btn.addEventListener('touchstart', startDrag, { passive: false });
      document.addEventListener('touchmove', doDrag, { passive: false });
      document.addEventListener('touchend', endDrag, { passive: false });
      
      // Load saved position on page load
      loadPosition();
      // ========== END DRAG & DROP ==========
      
    })();
    {% endif %}
  </script>
  
  <script>
    // Globální helper pro CSRF token
    function getCSRFToken() {
      const meta = document.querySelector('meta[name="csrf-token"]');
      return meta ? meta.content : '';
    }
    
    // Helper pro fetch s CSRF tokenem
    function fetchWithCSRF(url, options = {}) {
      const token = getCSRFToken();
      
      if (!options.headers) {
        options.headers = {};
      }
      
      // Přidej CSRF token pro POST/PUT/DELETE requesty
      if (options.method && options.method.toUpperCase() !== 'GET') {
        options.headers['X-CSRFToken'] = token;
      }
      
      return fetch(url, options);
    }
  </script>
  
</body>
</html>
"""


def render_page(
    content_html: str,
    ctx: Optional[Dict[str, Any]] = None,
    selected: Optional[int] = None,
) -> str:
    """Obali content_html do BASE_HTML sablony.

    Args:
        content_html: Jinja2 string s obsahem stranky.
        ctx:          Slovnik promennych pro sablonu.
        selected:     ID aktualne zvolene soute (override).

    Returns:
        Hotovy HTML string pro Flask response.
    """
    if ctx is None:
        ctx = {}

    rounds: list = []
    if current_user.is_authenticated:
        rounds = get_rounds_for_switch(selected)
        ensure_selected_round()

    # Odstran klice pridavane interně – zamezi konfliktu pri **ctx
    ctx.pop("rounds_for_switch", None)
    ctx.pop("selected_round_id_for_switch", None)
    ctx.pop("csrf_token", None)

    ctx["csrf_token"] = generate_csrf()

    inner = render_template_string(
        content_html,
        rounds_for_switch=rounds,
        selected_round_id_for_switch=selected,
        **ctx,
    )
    return render_template_string(
        BASE_HTML,
        content=inner,
        rounds_for_switch=rounds,
        selected_round_id_for_switch=selected,
        **ctx,
    )
