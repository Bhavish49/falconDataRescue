/**
 * falconDataRescue AI-Assisted Data Recovery Studio
 * Full Client-Side & Backend Forensic Recovery Engine
 * Implements Fragment Carving, Semantic Classification, PII Extraction,
 * Relationship Graphing, and Realism Assessment.
 */

// Use same-origin requests when FastAPI serves the UI. If the frontend is
// opened through Live Server, a file URL, or the old 8000 page, route API
// calls explicitly to the active recovery backend on 8010.
const localHost = ['localhost', '127.0.0.1', ''].includes(window.location.hostname);
const API_BASE_URL = localHost && window.location.port !== '8010'
  ? 'http://127.0.0.1:8010'
  : '';

let uploadedFiles = [];
let analyzedItems = [];
let currentInspectedIndex = 0;
let currentMode = 'files';

document.addEventListener('DOMContentLoaded', () => {
  initDropzone();
  initFileInputs();
  initRecoveryHandler();
  checkBackendHealth();
  initLandingNav();
});

function initLandingNav() {
  document.querySelectorAll('a[href^="#"]').forEach((link) => {
    link.addEventListener('click', (event) => {
      const target = document.querySelector(link.getAttribute('href'));
      if (!target) return;
      event.preventDefault();
      target.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
  });
}

function openRecoveryWorkspace() {
  document.body.classList.remove('landing-active');
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

function showLanding() {
  document.body.classList.add('landing-active');
  window.scrollTo({ top: 0, behavior: 'auto' });
}

// ==============================================================================
// 1. RECOVERY MODE & DEMO LOADER
// ==============================================================================

function setRecoveryMode(mode) {
  currentMode = mode;
  const btnFiles = document.getElementById('tab-btn-files');
  const btnDisk = document.getElementById('tab-btn-disk');
  const btnDrive = document.getElementById('tab-btn-drive');
  const titleText = document.getElementById('dropzone-title-text');
  const subText = document.getElementById('dropzone-sub-text');
  const fileBtns = document.getElementById('file-drop-buttons');
  const diskBtns = document.getElementById('disk-drop-buttons');
  const dropzone = document.getElementById('dropzone');
  const driveSection = document.getElementById('drive-section');

  btnFiles.classList.toggle('active', mode === 'files');
  btnDisk.classList.toggle('active', mode === 'disk');
  btnDrive.classList.toggle('active', mode === 'drive');

  if (mode === 'drive') {
    dropzone.style.display = 'none';
    driveSection.style.display = 'block';
    loadDriveList();
    return;
  }

  dropzone.style.display = '';
  driveSection.style.display = 'none';

  if (mode === 'files') {
    titleText.textContent = 'Drag & Drop Corrupted Files or Folders Here';
    subText.textContent = 'Multi-format recovery for JPEG, PNG, PDF, DOCX, XLSX, ZIP, text, and binary evidence.';
    fileBtns.style.display = 'flex';
    diskBtns.style.display = 'none';
  } else {
    titleText.textContent = 'Drag & Drop Raw Bitstream Disk Image (.dd / .raw / .img / .e01)';
    subText.textContent = 'Upload a forensic disk image; the engine will signature-carve unallocated bytes and report evidence, coverage, and fragments';
    fileBtns.style.display = 'none';
    diskBtns.style.display = 'flex';
  }
}

async function loadDemoSample(sampleType) {
  let filename = '';
  let sampleContent = '';

  if (sampleType === 'damaged_photo' || sampleType === 'photo') {
    try {
      const response = await fetch(`${API_BASE_URL}/api/repair/test-fixtures/synthetic-car`);
      if (!response.ok) throw new Error(`Fixture request failed (${response.status})`);
      const blob = await response.blob();
      const file = new File([blob], 'synthetic_car_damaged.jpg', { type: 'image/jpeg' });
      handleFilesIngested([file]);
      showToast('Loaded controlled-damage car fixture for safe pipeline testing', 'info');
      return;
    } catch (error) {
      console.warn('Synthetic car fixture unavailable; using fallback sample', error);
    }
  }

  if (sampleType === 'image_test_pack') {
    const fixtureNames = [
      'synthetic_car_damaged.jpg',
      'recoverable_missing_eoi.jpg',
      'recoverable_truncated_scan.jpg',
      'recoverable_prefix_only.jpg',
      'pixel_corrupted_valid_jpeg.jpg',
      'uniform_black_valid_jpeg.jpg',
      'invalid_jpeg_bytes.jpg',
    ];
    try {
      const files = await Promise.all(fixtureNames.map(async (fixtureName) => {
        const response = await fetch(`${API_BASE_URL}/api/repair/test-fixtures/${fixtureName}`);
        if (!response.ok) throw new Error(`Fixture request failed (${response.status})`);
        return new File([await response.blob()], fixtureName, { type: 'image/jpeg' });
      }));
      handleFilesIngested(files);
      showToast(`Loaded ${files.length} controlled image fixtures for batch testing`, 'info');
      return;
    } catch (error) {
      console.warn('Image test pack unavailable', error);
      showToast('Could not load the image test pack. Check the backend.', 'error');
      return;
    }
  }

  if (sampleType === 'java_notes') {
    filename = 'JAVA_NOTES_corrupted.pdf';
    // Raw corrupted PDF structure with embedded Java notes
    sampleContent = 
      'CORRUPTED_SECTOR_PREFIX_0xDEADBEEF\n' +
      '1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n' +
      '2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n' +
      '3 0 obj\n<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>\nendobj\n' +
      '4 0 obj\n<< /Length 280 >>\nstream\n' +
      'BT /F1 14 Tf (ADVANCED JAVA PROGRAMMING & OOP MASTER NOTES) Tj ET\n' +
      'BT /F1 11 Tf (1. Core Principles: Encapsulation, Inheritance, Polymorphism, Abstraction) Tj ET\n' +
      'BT /F1 10 Tf (2. JVM Architecture: ClassLoader, Method Area, Heap, Java Threads Stack) Tj ET\n' +
      'BT /F1 10 Tf (public class SingletonService { private static SingletonService instance; public static synchronized SingletonService getInstance() { return instance; } }) Tj ET\n' +
      'BT /F1 10 Tf (Instructor: prof.java@university.edu | Office: Room 402) Tj ET\n' +
      'endstream\nendobj\n' +
      'TRUNCATED_BAD_FOOTER_NO_XREF';
  } else if (sampleType === 'contract') {
    filename = 'corrupted_contract.pdf';
    sampleContent = 
      'BAD_HEADER_GARBAGE\n' +
      '1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n' +
      '2 0 obj\n<< /Type /Page /Contents 3 0 R >>\nendobj\n' +
      '3 0 obj\n<< /Length 120 >>\nstream\n' +
      'BT /F1 12 Tf (NON-DISCLOSURE AND SERVICE LEVEL AGREEMENT) Tj ET\n' +
      'BT /F1 10 Tf (The Parties agree to maintain strict confidentiality of proprietary data.) Tj ET\n' +
      'BT /F1 10 Tf (Executed by: legal@enterprise-corp.com) Tj ET\n' +
      'endstream\nendobj\n';
  } else {
    filename = 'damaged_photo.jpg';
    sampleContent = 'TRUNCATED_JPEG_STREAM\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00' + 'X'.repeat(200);
  }

  const blob = new Blob([sampleContent], { type: 'application/octet-stream' });
  const file = new File([blob], filename, { type: 'application/octet-stream' });
  handleFilesIngested([file]);
  showToast(`Loaded sample test file: ${filename}`, 'info');
}

// ==============================================================================
// 2. DROPZONE & INGESTION
// ==============================================================================

function initDropzone() {
  const dropzone = document.getElementById('dropzone');
  if (!dropzone) return;

  ['dragenter', 'dragover'].forEach(name => {
    dropzone.addEventListener(name, (e) => {
      e.preventDefault();
      dropzone.classList.add('dragover');
    });
  });

  ['dragleave', 'drop'].forEach(name => {
    dropzone.addEventListener(name, (e) => {
      e.preventDefault();
      dropzone.classList.remove('dragover');
    });
  });

  dropzone.addEventListener('drop', (e) => {
    const files = Array.from(e.dataTransfer.files);
    if (files.length > 0) handleFilesIngested(files);
  });
}

function initFileInputs() {
  ['file-input', 'folder-input'].forEach(id => {
    const input = document.getElementById(id);
    if (input) {
      input.addEventListener('change', (e) => {
        const files = Array.from(e.target.files);
        if (files.length > 0) handleFilesIngested(files);
        input.value = '';
      });
    }
  });

  const diskInput = document.getElementById('disk-input');
  if (diskInput) {
    diskInput.addEventListener('change', (e) => {
      const files = Array.from(e.target.files);
      if (files.length > 0) handleDiskImageIngested(files[0]);
      diskInput.value = '';
    });
  }
}

function clearUploadQueue() {
  uploadedFiles = [];
  analyzedItems = [];
  document.getElementById('workspace-section').style.display = 'none';
  document.getElementById('restored-section').style.display = 'none';
  showToast('Cleared workspace queue.', 'info');
}

// ==============================================================================
// 3. FORENSIC CLASSIFICATION & CLIENT CARVER
// ==============================================================================

function calculateEntropyClient(uint8) {
  if (!uint8 || uint8.length === 0) return 0;
  const counts = new Uint32Array(256);
  for (let i = 0; i < uint8.length; i++) counts[uint8[i]]++;
  let entropy = 0;
  for (let i = 0; i < 256; i++) {
    if (counts[i] > 0) {
      const p = counts[i] / uint8.length;
      entropy -= p * Math.log2(p);
    }
  }
  return parseFloat(entropy.toFixed(3));
}

function estimateClientDamageScore(filename, bytes, rawString, fragments, entropy) {
  const ext = filename.split('.').pop().toLowerCase();
  const signatures = {
    pdf: [0x25, 0x50, 0x44, 0x46, 0x2d],
    png: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a],
    jpg: [0xff, 0xd8, 0xff],
    jpeg: [0xff, 0xd8, 0xff],
    exe: [0x4d, 0x5a],
    dll: [0x4d, 0x5a],
  };
  const expected = signatures[ext];
  const hasExpectedHeader = expected
    ? expected.every((value, index) => bytes[index] === value)
    : null;
  const printableRatio = bytes.length
    ? Array.from(bytes).filter(value => value === 9 || value === 10 || value === 13 || (value >= 32 && value <= 126)).length / bytes.length
    : 0;

  let score = 8;
  if (bytes.length < 32) score += 28;
  if (expected && !hasExpectedHeader) score += 32;
  if (fragments.length === 0 && printableRatio < 0.25) score += 10;
  if (entropy < 1.0) score += 20;
  else if (entropy < 3.0) score += 8;
  else if (entropy > 7.8 && !['jpg', 'jpeg', 'png', 'zip', 'exe', 'dll'].includes(ext)) score += 8;
  if (rawString.includes('\ufffd')) score += 6;

  return Math.min(100, Math.max(5, Math.round(score)));
}

function extractTextFragmentsClient(rawString, ext) {
  const fragments = [];

  // JPEG/PNG files are binary media. Rendering arbitrary bytes as text creates
  // misleading glyph garbage and is not evidence recovery.
  if (['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp'].includes(ext)) return fragments;
  
  // 1. PDF operators
  const tjMatches = rawString.match(/\((.*?)\)\s*Tj/g);
  if (tjMatches) {
    tjMatches.forEach(m => {
      const clean = m.replace(/^\(/, '').replace(/\)\s*Tj$/, '').trim();
      if (clean.length > 1) fragments.push(clean);
    });
  }

  // 2. Direct string runs
  if (fragments.length < 3) {
    const matches = rawString.match(/[\w\s.,;:{}()\[\]=+\-/*"'\\]{8,}/g);
    if (matches) {
      matches.forEach(m => {
        const c = m.trim();
        if (c.length > 6 && !c.startsWith('<<') && !c.startsWith('>>') && !c.startsWith('obj')) {
          fragments.push(c);
        }
      });
    }
  }

  // Deduplicate
  return Array.from(new Set(fragments));
}

function classifyClient(filename, fragments) {
  const full = (filename + " " + fragments.join(" ")).toLowerCase();
  
  // Rules
  if (full.includes("java") || full.includes("class ") || full.includes("public static") || full.includes("jvm") || full.includes("notes") || full.includes("polymorphism") || full.includes("inheritance")) {
    return { category: "📚 Educational & Technical Notes", priority: "P1", priorityClass: "badge-p1" };
  }
  if (full.includes("agreement") || full.includes("contract") || full.includes("confidentiality") || full.includes("parties") || full.includes("executed")) {
    return { category: "💼 Legal & Contracts", priority: "P1", priorityClass: "badge-p1" };
  }
  if (full.includes("invoice") || full.includes("total") || full.includes("amount") || full.includes("tax") || full.includes("balance") || full.includes("usd") || full.includes("inr")) {
    return { category: "📊 Financial & Accounting", priority: "P1", priorityClass: "badge-p1" };
  }
  if (full.includes("import") || full.includes("function") || full.includes("const") || full.includes("return") || full.includes("def ")) {
    return { category: "💻 Software Source Code", priority: "P2", priorityClass: "badge-p2" };
  }
  const ext = filename.split('.').pop().toLowerCase();
  if (['jpg', 'jpeg', 'png', 'bmp', 'webp'].includes(ext)) {
    return { category: "🖼️ Visual Media & Photography", priority: "P3", priorityClass: "badge-p3" };
  }
  return { category: "📄 General Digital Document", priority: "P2", priorityClass: "badge-p2" };
}

function extractEntitiesClient(text) {
  const entities = [];
  
  // Emails
  const emails = text.match(/[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+/g);
  if (emails) entities.push({ type: "Email", values: Array.from(new Set(emails)) });

  // Java Classes
  const javaClasses = text.match(/(?:class|interface)\s+([A-Z][a-zA-Z0-9_]+)/g);
  if (javaClasses) {
    const cleaned = javaClasses.map(c => c.split(/\s+/)[1]);
    entities.push({ type: "Java Class", values: Array.from(new Set(cleaned)) });
  }

  // Phone numbers
  const phones = text.match(/(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/g);
  if (phones) entities.push({ type: "Phone", values: Array.from(new Set(phones)) });

  return entities;
}

// Ingest files & diagnose
async function handleFilesIngested(files) {
  const selectedFiles = files.filter(file => file.size > 0);
  if (selectedFiles.length === 0) {
    showToast('Select at least one non-empty file.', 'warning');
    return;
  }

  uploadedFiles = selectedFiles;
  document.getElementById('workspace-section').style.display = 'block';
  document.getElementById('total-files-count').textContent = selectedFiles.length;
  document.getElementById('restored-section').style.display = 'none';

  analyzedItems = [];
  for (let i = 0; i < selectedFiles.length; i++) {
    const file = selectedFiles[i];
    const buffer = await file.arrayBuffer();
    const uint8 = new Uint8Array(buffer);
    const textDecoder = new TextDecoder('utf-8', { fatal: false });
    const rawString = textDecoder.decode(uint8);
    const ext = file.name.split('.').pop().toLowerCase();

    const entropy = calculateEntropyClient(uint8);
    const fragments = extractTextFragmentsClient(rawString, ext);
    const classification = classifyClient(file.name, fragments);
    const entities = extractEntitiesClient(file.name + " " + fragments.join(" "));

    const damageScore = estimateClientDamageScore(file.name, uint8, rawString, fragments, entropy);

    analyzedItems.push({
      file_name: file.name,
      size_bytes: file.size,
      extension: ext,
      raw_bytes: uint8,
      raw_string: rawString,
      entropy: entropy,
      fragments: fragments,
      classification: classification,
      entities: entities,
      damage_score: damageScore,
      health_score: 100 - damageScore
    });
  }

  renderDiagnosticsList();
  showToast(`Loaded ${selectedFiles.length} file(s). Running pre-recovery evidence analysis...`, 'info');
  await enrichWithBackendDiagnosis(selectedFiles);
}

async function enrichWithBackendDiagnosis(files) {
  const attachDiagnoses = (items) => {
    items.forEach(diagnosis => {
      const item = analyzedItems.find(candidate => candidate.file_name === diagnosis.file_name);
      if (item) item.backend_diagnosis = diagnosis;
    });
  };

  try {
    const formData = new FormData();
    files.forEach(file => formData.append('files', file));
    const response = await fetch(`${API_BASE_URL}/api/repair/diagnose`, {
      method: 'POST',
      body: formData,
    });
    if (!response.ok) throw new Error(`Pre-analysis failed (${response.status})`);
    const data = await response.json();
    attachDiagnoses(data.items);
    renderDiagnosticsList();
    showToast('Pre-recovery evidence analysis complete. Review fragments before starting recovery.', 'success');
  } catch (error) {
    // A single large or unusual file should not hide diagnosis for every other file.
    const individualDiagnoses = [];
    for (const file of files) {
      try {
        const formData = new FormData();
        formData.append('files', file);
        const response = await fetch(`${API_BASE_URL}/api/repair/diagnose`, { method: 'POST', body: formData });
        if (response.ok) {
          const data = await response.json();
          if (data.items?.[0]) individualDiagnoses.push(data.items[0]);
        }
      } catch (individualError) {
        console.warn(`Could not diagnose ${file.name}`, individualError);
      }
    }

    if (individualDiagnoses.length > 0) {
      attachDiagnoses(individualDiagnoses);
      renderDiagnosticsList();
      showToast(`Evidence analysis completed for ${individualDiagnoses.length}/${files.length} file(s).`, 'warning');
    } else {
      console.warn('Backend pre-analysis unavailable; showing local analysis only.', error);
      showToast('Backend pre-analysis unavailable; per-file local evidence analysis is shown.', 'warning');
    }
  }
}

function plannedRecoveryActions(item) {
  const d = item.backend_diagnosis || {};
  const ext = (item.extension || '').toLowerCase();
  const actions = [];
  if (d.is_header_damaged) actions.push('Rewrite the missing/corrupted magic header');
  if (d.is_footer_damaged) actions.push('Restore the truncated EOF footer marker');
  if (ext === 'pdf') {
    actions.push('Rebuild the PDF object tree and xref offsets');
    actions.push('Decompress and salvage FlateDecode text streams');
  } else if (ext === 'jpg' || ext === 'jpeg' || ext === 'png') {
    actions.push('Validate SOI/EOI (JPEG) or chunk markers (PNG)');
    actions.push('Rebuild container markers and attempt pixel reconstruction');
  } else if (ext === 'docx' || ext === 'xlsx' || ext === 'zip') {
    actions.push('Rebuild Office/ZIP package entries from salvaged XML parts');
  } else {
    actions.push('Carve readable text/code fragments from the byte stream');
    actions.push('Preserve the original bytes alongside extracted content');
  }
  actions.push('Score integrity and only offer downloads for validated output');
  return actions;
}

function buildAnalysisPanelHTML(a, uid) {
  const issueRows = (a.issues && a.issues.length)
    ? a.issues.map(t => `<div class="analysis-issue">&#9888; ${escapeHtml(t)}</div>`).join('')
    : '<div class="analysis-ok">&#10003; No structural problems detected in format markers or container boundaries.</div>';

  const chips = [];
  if (a.headerOk !== null && a.headerOk !== undefined) {
    chips.push(`<span class="analysis-chip ${a.headerOk ? 'ok' : 'bad'}">Header: ${a.headerOk ? 'intact' : 'damaged / missing'}</span>`);
  }
  if (a.footerOk !== null && a.footerOk !== undefined) {
    chips.push(`<span class="analysis-chip ${a.footerOk ? 'ok' : 'bad'}">EOF footer: ${a.footerOk ? 'intact' : 'truncated'}</span>`);
  }
  if (a.recoverability) {
    const cls = a.recoverability === 'high' ? 'ok' : a.recoverability === 'medium' ? 'warn' : 'bad';
    chips.push(`<span class="analysis-chip ${cls}">Recoverability: ${escapeHtml(a.recoverability)}</span>`);
  }
  if (a.status) chips.push(`<span class="analysis-chip warn">Status: ${escapeHtml(a.status)}</span>`);
  if (a.confidence !== null && a.confidence !== undefined) {
    chips.push(`<span class="analysis-chip ${a.confidence >= 60 ? 'ok' : 'bad'}">Confidence: ${escapeHtml(String(a.confidence))}%</span>`);
  }

  const facts = [
    ['Detected type', a.detectedType],
    ['Size', a.sizeBytes != null ? formatBytes(a.sizeBytes) : null],
    ['Entropy H(x)', a.entropy],
    ['Null-byte ratio', a.nullRatio != null ? `${a.nullRatio}%` : null],
    ['Fragments detected', a.fragments],
    ['Integrity (evidence)', a.integrityScore != null ? `${a.integrityScore}%` : null],
  ].filter(([, v]) => v !== null && v !== undefined && v !== '');
  const factRows = facts
    .map(([k, v]) => `<div class="analysis-fact"><span>${escapeHtml(k)}</span><strong>${escapeHtml(String(v))}</strong></div>`)
    .join('');

  const noteRows = (a.notes || [])
    .map(t => `<div class="analysis-note">&bull; ${escapeHtml(t)}</div>`)
    .join('');

  return `
    <div class="analysis-panel" id="analysis-${uid}" style="display:none;">
      <div class="analysis-title">Problem analysis &mdash; what is wrong with this file</div>
      <div class="analysis-issues">${issueRows}</div>
      <div class="analysis-chips">${chips.join('')}</div>
      <div class="analysis-facts">${factRows}</div>
      ${noteRows ? `<div class="analysis-notes"><div class="analysis-subtitle">What recovery will attempt</div>${noteRows}</div>` : ''}
    </div>`;
}

function toggleAnalysis(uid, btn) {
  const el = document.getElementById(`analysis-${uid}`);
  if (!el) return;
  const open = el.style.display === 'block';
  el.style.display = open ? 'none' : 'block';
  btn.textContent = open ? 'View Problem Analysis' : 'Hide Problem Analysis';
}

function queueAnalysisSummaryHTML() {
  const total = analyzedItems.length;
  const problematic = analyzedItems.filter(i => {
    const d = i.backend_diagnosis || {};
    return (d.issues && d.issues.length) || i.damage_score > 0;
  }).length;
  const healthy = total - problematic;
  const avgIntegrity = total
    ? Math.round(analyzedItems.reduce((sum, i) => {
      const d = i.backend_diagnosis || {};
      const score = Number.isFinite(Number(d.integrity_assessment?.score))
        ? Number(d.integrity_assessment.score)
        : 100 - i.damage_score;
      return sum + score;
    }, 0) / total)
    : 0;
  return `
    <div class="analysis-summary">
      <div><strong>${total}</strong> file(s) analyzed</div>
      <div class="${problematic ? 'bad' : 'ok'}"><strong>${problematic}</strong> with problems</div>
      <div class="ok"><strong>${healthy}</strong> healthy</div>
      <div><strong>${avgIntegrity}%</strong> avg integrity</div>
      <div class="analysis-summary-note">Review each file's problem analysis before starting recovery. Downloads are only offered for validated output.</div>
    </div>`;
}

function renderDiagnosticsList() {
  const container = document.getElementById('file-queue-list');
  if (!container) return;

  const rows = analyzedItems.map((item, idx) => {
    const diagnosis = item.backend_diagnosis || {};
    const integrity = diagnosis.integrity_assessment || {};
    const integrityScore = Number.isFinite(Number(integrity.score))
      ? Number(integrity.score)
      : 100 - item.damage_score;
    const damageScore = Number.isFinite(Number(diagnosis.damage_score))
      ? Number(diagnosis.damage_score)
      : item.damage_score;
    const fragmentCount = diagnosis.fragments_detected ?? item.fragments.length;
    const imageCandidateCount = diagnosis.image_candidates?.length || 0;
    const issues = diagnosis.issues && diagnosis.issues.length
      ? ` • ${diagnosis.issues.length} issue(s)`
      : '';
    item._diagnosisSummary = { diagnosis, integrity, fragmentCount, integrityScore, damageScore };

    const analysis = {
      detectedType: diagnosis.detected_type,
      sizeBytes: item.size_bytes,
      entropy: item.entropy,
      nullRatio: diagnosis.null_byte_ratio,
      fragments: fragmentCount,
      integrityScore,
      issues: diagnosis.issues || [],
      headerOk: diagnosis.is_header_damaged === undefined ? null : !diagnosis.is_header_damaged,
      footerOk: diagnosis.is_footer_damaged === undefined ? null : !diagnosis.is_footer_damaged,
      recoverability: integrity.recoverability || null,
      status: null,
      confidence: null,
      notes: plannedRecoveryActions(item),
    };

    return `
    <div class="file-row">
      <div class="file-info">
        <div class="file-icon">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
          </svg>
        </div>
        <div>
          <div class="file-name">${escapeHtml(item.file_name)}</div>
          <div class="file-meta">
            ${formatBytes(item.size_bytes)} • H(x)=${item.entropy} • ${item._diagnosisSummary.fragmentCount} fragments${imageCandidateCount ? ` • ${imageCandidateCount} image candidate(s)` : ''}${item._diagnosisSummary.diagnosis.detected_type ? ` • ${escapeHtml(item._diagnosisSummary.diagnosis.detected_type)}` : ''}${issues}
          </div>
        </div>
      </div>

      <div>
        <span class="badge ${item.classification.priorityClass}">
          ${escapeHtml(item.classification.priority)} • ${escapeHtml(item.classification.category)}
        </span>
      </div>

      <div>
        <div style="font-size: 11px; color: var(--text-muted); font-family: var(--font-mono);">
          INTEGRITY (EVIDENCE): <strong title="Format markers, structural checks, entropy, and recoverable fragments—not a guarantee of complete file contents." style="color: ${integrityScore > 60 ? 'var(--emerald)' : 'var(--rose)'};">${integrityScore}%</strong>
        </div>
        <div class="damage-bar-track">
          <div class="damage-bar-fill" style="width: ${damageScore}%;"></div>
        </div>
      </div>

      <div style="display: flex; flex-direction: column; gap: 6px; align-items: flex-end;">
        <button class="btn btn-secondary btn-sm" onclick="openInspectorModal(${idx})">Inspect Fragments</button>
        <button class="btn btn-secondary btn-sm" onclick="toggleAnalysis('q${idx}', this)">View Problem Analysis</button>
      </div>

      ${buildAnalysisPanelHTML(analysis, `q${idx}`)}
    </div>
  `;
  }).join('');

  container.innerHTML = queueAnalysisSummaryHTML() + rows;
}

// ==============================================================================
// 3.5 DISK IMAGE HANDLING
// ==============================================================================

async function handleDiskImageIngested(file) {
  showToast(`Uploading raw disk image ${file.name} for carving...`, 'info');
  document.getElementById('workspace-section').style.display = 'block';
  document.getElementById('restored-section').style.display = 'none';
  document.getElementById('file-queue-list').innerHTML = '<div style="padding: 20px; text-align: center; color: var(--cyan);">Uploading and carving disk image via PyTSK3 engine. Please wait...</div>';
  document.getElementById('total-files-count').textContent = 'Disk Image';

  try {
    const formData = new FormData();
    formData.append('file', file);

    const res = await fetch(`${API_BASE_URL}/api/forensics/carve-image`, {
      method: 'POST',
      body: formData
    });

    if (res.ok) {
      const data = await res.json();
      showToast(`Carving complete. Found ${data.total_recovered} candidate(s); ${data.validated_candidates || 0} passed format validation.`, 'success');
      
      const formattedItems = data.items.map(item => ({
        id: 'carved:' + item.id,
        file_name: item.filename,
        deleted_candidate: true,
        report: {
          category: item.type,
          status: item.status === 'VALIDATED_CARVE' ? 'VALIDATED_REPAIR' : 'PARTIAL_RECOVERY',
          confidence: Number.parseInt(item.confidence, 10) || 0,
          integrity_score: Number.parseInt(item.confidence, 10) || 0,
          confidence_scope: item.confidence_scope,
          deletion_proven: item.deletion_proven,
          deletion_status: item.deletion_status,
          original_filename: item.original_filename,
          filename_basis: item.filename_basis,
          recovered_percentage: item.recovered_percentage,
          validated_range_percentage: item.validated_range_percentage,
          coverage_basis: item.coverage_basis,
          missing_bytes: item.missing_bytes,
          fragments: item.fragments || [],
          sha256: item.sha256,
          realism_assessment: `${item.deletion_proven ? 'Deleted-file status confirmed by filesystem metadata.' : 'Signature-carved candidate; deletion is not proven without filesystem metadata.'} ${item.recovered_percentage == null ? `Original-file coverage is unknown; validated marker range: ${item.validated_range_percentage == null ? 'not complete' : `${item.validated_range_percentage}%`}.` : `Validated original-file coverage: ${item.recovered_percentage}%.`} ${item.note || ''}`,
          warnings: [
            item.note,
            `Fragment evidence: ${(item.fragments || []).length} contiguous fragment(s) at ${item.hex_offset}.`,
            item.recovered_percentage == null ? 'Missing-byte percentage cannot be calculated from a raw signature carve.' : null,
          ].filter(Boolean),
          download_available: true
        }
      }));
      
      renderRestoredResults(formattedItems, true);
      
      const bundleBtn = document.getElementById('btn-download-bundle');
      bundleBtn.onclick = () => {
        window.location.href = `${API_BASE_URL}/api/forensics/download-carved/${data.bundle_id}`;
      };
      
      document.getElementById('workspace-section').style.display = 'none';
    } else {
      showToast('Error carving disk image.', 'error');
    }
  } catch (e) {
    showToast('Network error while carving disk image.', 'error');
    console.error(e);
  }
}

// ==============================================================================
// 3.6 DELETED-FILE RECOVERY VIA NTFS DRIVE SCAN (NO RECYCLE BIN)
// ==============================================================================

async function loadDriveList() {
  const sel = document.getElementById('drive-select');
  const scanButton = sel?.parentElement?.querySelector('button');
  if (!sel) return;
  sel.disabled = true;
  if (scanButton) scanButton.disabled = true;
  sel.innerHTML = '<option value="">Detecting drives...</option>';
  try {
    const res = await fetch(`${API_BASE_URL}/api/deleted/drives`);
    if (!res.ok) throw new Error(`Drive enumeration failed (${res.status})`);
    const data = await res.json();
    const drives = data.drives || [];
    sel.innerHTML = drives.length
      ? drives
      .map(d => `<option value="${escapeHtml(d.letter)}">${escapeHtml(d.letter)}: — ${escapeHtml(d.kind)} drive</option>`)
      .join('')
      : '<option value="">No NTFS-compatible drives detected</option>';
    if (drives.length) {
      sel.value = drives[0].letter;
      sel.disabled = false;
      if (scanButton) scanButton.disabled = false;
    }
  } catch (e) {
    console.error(e);
    sel.innerHTML = '<option value="">Unable to enumerate drives</option>';
  }
}

async function scanDriveForDeleted() {
  const drive = document.getElementById('drive-select').value;
  if (!drive) {
    showToast('No drive selected.', 'error');
    return;
  }
  const list = document.getElementById('drive-scan-list');
  document.getElementById('drive-scan-banner').style.display = 'none';
  list.innerHTML = `<div style="padding: 20px; text-align: center; color: var(--cyan);">Scanning ${escapeHtml(drive)}: NTFS metadata for deleted file records... bounded to ~20s, partial results are returned for very large drives.</div>`;
  try {
    const res = await fetch(`${API_BASE_URL}/api/deleted/scan-drive`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ drive })
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Scan failed (${res.status})`);
    }
    const data = await res.json();
    renderDriveScanResults(data);
  } catch (e) {
    console.error(e);
    list.innerHTML = `<div style="padding: 20px; text-align: center; color: var(--rose);">${escapeHtml(e.message)}</div>`;
    showToast(e.message || 'Drive scan failed.', 'error');
  }
}

function renderDriveScanResults(data) {
  const list = document.getElementById('drive-scan-list');
  const banner = document.getElementById('drive-scan-banner');
  if (!data.items || !data.items.length) {
    list.innerHTML = `<div style="padding: 20px; text-align: center; color: var(--text-muted);">No recoverable deleted file records found on ${escapeHtml(data.source)} (${data.records_scanned} records scanned).</div>`;
    banner.style.display = 'none';
    showToast('No recoverable deleted files found.', 'info');
    return;
  }
  const stoppedNote = data.scan_stopped
    ? `Scan stopped early: ${escapeHtml(data.scan_stopped)} &mdash; showing the artifacts found so far.`
    : 'Full $MFT scan completed.';
  const summary = `
    <div class="analysis-summary">
      <div><strong>${data.items.length}</strong> deleted record(s) recovered</div>
      <div><strong>${escapeHtml(String(data.records_scanned))}</strong> of ${escapeHtml(String(data.records_available ?? data.records_scanned))} $MFT records scanned</div>
      <div class="ok"><strong>deletion proven</strong> by filesystem metadata</div>
      <div class="analysis-summary-note">${stoppedNote} Each entry below lists its problem analysis and evidence before download. Clusters of deleted files may be partially overwritten &mdash; confidence reflects validated reassembly, not a guarantee of complete contents.</div>
    </div>`;

  list.innerHTML = summary + data.items.map((item, idx) => {
    const confidence = Number.parseInt(item.confidence, 10) || 0;
    const coverage = item.recovered_percentage;
    const issues = [];
    issues.push('File record is marked deleted in the NTFS $MFT (entry no longer in use).');
    if (coverage == null) issues.push('Original-file coverage cannot be determined from this record; validated marker/run range only.');
    else if (coverage < 100) issues.push(`Approximately ${100 - coverage}% of the original data runs are missing or unreferenced.`);
    if (!item.deletion_proven) issues.push('Deletion could not be proven by filesystem metadata for this record.');

    const analysis = {
      detectedType: item.type,
      sizeBytes: item.size_bytes,
      entropy: null,
      nullRatio: null,
      fragments: (item.fragments || []).length,
      integrityScore: confidence,
      issues,
      headerOk: null,
      footerOk: null,
      recoverability: coverage == null ? null : (coverage >= 90 ? 'high' : coverage >= 50 ? 'medium' : 'low'),
      status: item.status,
      confidence,
      notes: [
        'Reassemble the data runs listed in the deleted $MFT record',
        'Verify the reassembled payload against its sha256 digest',
        'Offer download only for the validated reassembled bytes',
      ],
    };

    return `
    <div class="file-row">
      <div class="file-info">
        <div>
          <div class="file-name">${escapeHtml(item.filename)}</div>
          <div class="file-meta">
            ${escapeHtml(item.type)} • ${formatBytes(item.size_bytes)} • ${(item.fragments || []).length} fragment(s) • deletion proven by $MFT metadata • sha256 ${escapeHtml((item.sha256 || '').slice(0, 12))}…
          </div>
        </div>
      </div>
      <div>
        <button class="btn btn-secondary btn-sm" onclick="toggleAnalysis('d${idx}', this)">View Problem Analysis</button>
      </div>
      <div>
        <a class="btn btn-secondary btn-sm" href="${API_BASE_URL}/api/deleted/download/${item.id}">Download</a>
      </div>
      ${buildAnalysisPanelHTML(analysis, `d${idx}`)}
    </div>`;
  }).join('');
  banner.style.display = 'flex';
  document.getElementById('btn-download-deleted-bundle').onclick = () => {
    window.location.href = `${API_BASE_URL}/api/deleted/download/${data.bundle_id}`;
  };
  showToast(`Recovered ${data.total_recovered} deleted file(s) from ${data.source}.`, 'success');
}

// ==============================================================================
// 4. RECOVERY EXECUTION & RESULT DISPLAY
// ==============================================================================

function initRecoveryHandler() {
  const btn = document.getElementById('btn-start-repair');
  if (!btn) return;

  btn.addEventListener('click', async () => {
    if (analyzedItems.length === 0) {
      showToast('Please upload corrupted files first.', 'warning');
      return;
    }

    btn.disabled = true;
    btn.innerHTML = `<span style="display:inline-block; animation:spin 1s linear infinite;">⏳</span> Carving Fragments & Reconstructing Objects...`;
    showToast('Scanning image bytes and validating recoverable ranges...', 'info');

    // Queue backend recovery and poll until deterministic validation + AI review finish.
    let backendSuccess = false;
    let repairedCount = 0;
    let originalCount = 0;
    try {
      const formData = new FormData();
      uploadedFiles.forEach(f => formData.append('files', f));

      const queued = await fetch(`${API_BASE_URL}/api/repair/jobs`, {
        method: 'POST',
        body: formData
      });
      if (!queued.ok) {
        let detail = '';
        try {
          const errorBody = await queued.json();
          detail = errorBody.detail || errorBody.error || '';
        } catch (_) {
          detail = await queued.text();
        }
        throw new Error(`Recovery request failed (${queued.status})${detail ? `: ${detail}` : ''}`);
      }
      const { job_id: jobId } = await queued.json();
      const data = await waitForRecoveryJob(jobId);
      if (data.status !== 'completed') throw new Error(data.error || 'Recovery job failed');
      renderRestoredResults(data.items, true, data.bundle_id);
      repairedCount = data.items.filter(item => item.id && item.report?.status !== 'ORIGINAL_VALID').length;
      originalCount = data.items.filter(item => item.report?.status === 'ORIGINAL_VALID').length;
      backendSuccess = true;
    } catch (e) {
      console.error('Image recovery backend unavailable.', e);
      showToast(e.message || 'Recovery request could not reach the backend.', 'error');
    }

    if (!backendSuccess) {
      btn.disabled = false;
      btn.innerHTML = 'Start Recovery Job';
      return;
    }

    btn.disabled = false;
    btn.innerHTML = repairedCount
      ? `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg> Recovery Complete`
      : 'No Repairs Needed';
    showToast(
      repairedCount
        ? `Validated ${repairedCount} repaired file(s). ${originalCount ? `${originalCount} original file(s) needed no repair.` : ''}`
        : `${originalCount} original file(s) validated. No repair was needed.`,
      repairedCount || originalCount ? 'success' : 'warning'
    );
  });
}

function synthesizeCleanFile(item) {
  const ext = item.extension;
  if (ext === 'pdf') {
    // Generate valid raw PDF stream
    let contentStream = '';
    let y = 670;
    item.fragments.forEach(f => {
      const safe = f.replace(/[()]/g, '');
      contentStream += `BT /F1 10 Tf 50 ${y} Td (${safe}) Tj ET\n`;
      y -= 24;
    });

    const streamLen = contentStream.length;

    // Calculate proper offsets for xref table
    let offset = 0;
    const obj1Offset = offset;
    const obj1 = '1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n';
    offset += obj1.length;

    const obj2Offset = offset;
    const obj2 = '2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n';
    offset += obj2.length;

    const obj3Offset = offset;
    const obj3 = '3 0 obj\n<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> >> >> /Contents 4 0 R >>\nendobj\n';
    offset += obj3.length;

    const obj4Offset = offset;
    const obj4 = `4 0 obj\n<< /Length ${streamLen} >>\nstream\n${contentStream}endstream\nendobj\n`;
    offset += obj4.length;

    const xrefOffset = offset;
    const xrefHeader = 'xref\n0 5\n';
    offset += xrefHeader.length;

    // Add xref entries (6 bytes for offset + 1 space + 5 digits for generation + 1 space + 'n' or 'f' + 1 newline)
    const xrefEntries =
      '0000000000 65535 f \n' +           // free object
      padOffset(obj1Offset) + '00000 n \n' +
      padOffset(obj2Offset) + '00000 n \n' +
      padOffset(obj3Offset) + '00000 n \n' +
      padOffset(obj4Offset) + '00000 n \n';
    offset += xrefEntries.length;

    const trailer =
      'trailer\n<< /Size 5 /Root 1 0 R >>\n';
    offset += trailer.length;

    const startxrefOffset = offset;
    const startxref = `startxref\n${startxrefOffset}\n%%EOF`;

    const cleanPdf =
      '%PDF-1.4\n' +
      obj1 +
      obj2 +
      obj3 +
      obj4 +
      xrefHeader +
      xrefEntries +
      trailer +
      startxref;

    return new Blob([cleanPdf], { type: 'application/pdf' });
  }

  return new Blob([item.raw_bytes], { type: 'application/octet-stream' });
}

function padOffset(offset) {
  return offset.toString().padStart(10, '0');
}

async function waitForRecoveryJob(jobId) {
  while (true) {
    const res = await fetch(`${API_BASE_URL}/api/repair/jobs/${jobId}`);
    if (!res.ok) throw new Error(`Recovery status request failed (${res.status})`);
    const job = await res.json();
    showToast(`${job.status.replace('_', ' ')} • ${job.progress}%`, 'info');
    if (['completed', 'failed'].includes(job.status)) return job;
    await new Promise(resolve => setTimeout(resolve, 1000));
  }
}

function renderRestoredResults(items, isBackend, bundleId) {
  const section = document.getElementById('restored-section');
  const container = document.getElementById('restored-file-list');
  const bundleBtn = document.getElementById('btn-download-bundle');

  items.forEach((result, idx) => {
    if (!analyzedItems[idx]) {
      const report = result.report || {};
      analyzedItems[idx] = {
        file_name: result.file_name || `carved_candidate_${idx + 1}`,
        size_bytes: report.original_size || 0,
        extension: (result.file_name || '').split('.').pop().toLowerCase(),
        raw_bytes: new Uint8Array(),
        raw_string: '',
        entropy: 0,
        fragments: (report.fragments || []).map(fragment =>
          `Fragment at offset ${fragment.offset} (${fragment.length} bytes; ${fragment.fragment_status || 'carved'})`
        ),
        entities: [],
        classification: {
          category: report.category || 'Deleted-file candidate',
          priority: 'P2',
          priorityClass: 'badge-p2'
        },
        damage_score: 100 - Number(report.integrity_score || 0),
        health_score: Number(report.integrity_score || 0),
      };
    }
    analyzedItems[idx].recovery_report = result.report || {};
  });

  section.style.display = 'block';
  bundleBtn.style.display = bundleId ? 'inline-flex' : 'none';
  bundleBtn.onclick = bundleId
    ? () => { window.location.href = `${API_BASE_URL}/api/repair/download/${bundleId}`; }
    : null;

  container.innerHTML = items.map((item, idx) => {
    const rep = item.report || {};
    const originalValid = rep.status === 'ORIGINAL_VALID' || rep.content_recovery_status === 'original_validated';
    const failed = !originalValid && (rep.status === 'FAILED_RECOVERY' || rep.download_available === false);
    const partial = !failed && rep.status === 'PARTIAL_RECOVERY';
    const decodedOnly = !failed && rep.content_recovery_status === 'decoded_without_pixel_repair';
    const confidence = decodedOnly
      ? (rep.pixel_recovery_confidence ?? 0)
      : (rep.confidence ?? rep.integrity_score ?? 0);
    const confidenceLabel = decodedOnly ? 'PIXEL CONFIDENCE' : 'CONFIDENCE';
    const badgeClass = failed ? 'badge-p1' : (partial || decodedOnly) ? 'badge-p2' : 'badge-success';
    const badgeText = failed
      ? '× RECOVERY FAILED'
      : originalValid
        ? '✓ ORIGINAL VALID'
      : decodedOnly
        ? '⚠ PIXELS NOT RECONSTRUCTED'
        : partial
          ? '△ PARTIAL RECOVERY'
          : '✓ RECOVERY READY';
    const resultMessage = failed
      ? [...(rep.warnings || []), rep.realism_assessment].filter(Boolean).join(' ')
      : [...(rep.warnings || []), rep.realism_assessment || (originalValid
        ? 'Original file validated; no repair was applied.'
        : decodedOnly
        ? 'The JPEG container is readable, but the original pixel content was not repaired.'
        : 'Image container repaired and validated by the image decoder.')].filter(Boolean).join(' ');
    const candidate = rep.scanner?.candidates?.[0];
    const deletedSummary = rep.deletion_status
      ? `Deleted status: ${rep.deletion_proven ? 'confirmed' : 'unconfirmed'} • ${rep.recovered_percentage == null ? `original coverage unknown; marker range ${rep.validated_range_percentage == null ? 'incomplete' : `${rep.validated_range_percentage}% validated`}` : `${rep.recovered_percentage}% validated coverage`}`
      : '';
    const scanSummary = originalValid
      ? 'Original validation: source bytes preserved; no repair applied'
      : candidate
      ? `Evidence scan: offset ${candidate.offset} • ${candidate.length} bytes • ${candidate.complete ? 'SOI/EOI markers found; decoder validation required' : 'truncated marker range'}`
      : rep.fragments?.length
        ? `Deleted-file evidence: ${rep.fragments.length} fragment(s) • ${deletedSummary}`
        : 'Evidence scan: no complete image marker range found';
    return `
      <div class="restored-card-item">
        <div class="restored-header-row">
          <div>
            <div style="font-size: 14px; font-weight: 700; color: var(--text-primary);">${escapeHtml(item.file_name)}</div>
            <div style="font-size: 11px; color: ${failed ? 'var(--rose)' : decodedOnly ? 'var(--amber)' : 'var(--emerald)'}; font-family: var(--font-mono); margin-top: 2px;">
              ${confidenceLabel}: ${escapeHtml(String(confidence))}% • ${escapeHtml(rep.status || 'RECOVERY RESULT')}
            </div>
          </div>
          <div>
            <span class="badge ${badgeClass}">${badgeText}</span>
          </div>
        </div>

        <div style="font-size: 12px; color: var(--text-secondary); line-height: 1.5;">
          ${escapeHtml(resultMessage || 'Image decoder could not validate the recovered bytes.')}
        </div>
        <div class="recovery-evidence">${escapeHtml(scanSummary)}${deletedSummary && candidate ? ` • ${escapeHtml(deletedSummary)}` : ''}</div>

        <div class="restored-actions-row">
          <button class="btn btn-secondary btn-xs" onclick="openInspectorModal(${idx})">
            🔍 View Extracted Notes & Graph
          </button>
          <button class="btn btn-secondary btn-xs" onclick="toggleAnalysis('r${idx}', this)">View Problem Analysis</button>
          ${item.id ? `<button class="btn btn-primary btn-xs" onclick="downloadRestoredFile(${idx}, '${item.id}')">💾 ${originalValid ? 'Download Original' : 'Download Recovered File'}</button>` : '<span class="badge badge-p1">NO VALID DOWNLOAD</span>'}
        </div>

        ${buildAnalysisPanelHTML({
          detectedType: rep.category,
          sizeBytes: rep.original_size,
          entropy: rep.entropy_before,
          nullRatio: null,
          fragments: rep.fragments?.length,
          integrityScore: rep.integrity_score,
          issues: rep.warnings || [],
          headerOk: null,
          footerOk: null,
          recoverability: null,
          status: rep.status,
          confidence,
          notes: rep.repair_actions || rep.operations || [],
        }, `r${idx}`)}
      </div>
    `;
  }).join('');

  section.scrollIntoView({ behavior: 'smooth' });
}

function downloadRestoredFile(idx, backendId) {
  if (backendId) {
    if (backendId.startsWith('carved:')) {
      window.location.href = `${API_BASE_URL}/api/forensics/download-carved/${backendId.split(':')[1]}`;
    } else {
      window.location.href = `${API_BASE_URL}/api/repair/download/${backendId}`;
    }
    return;
  }
  const item = analyzedItems[idx];
  const blob = synthesizeCleanFile(item);
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `restored_${item.file_name}`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  showToast(`Downloaded restored_${item.file_name}`, 'success');
}

// ==============================================================================
// 5. DEEP INSPECTOR MODAL & INTERACTIVE GRAPH
// ==============================================================================

function openInspectorModal(idx) {
  currentInspectedIndex = idx;
  const item = analyzedItems[idx];
  if (!item) return;
  const diagnosis = item.backend_diagnosis || {};
  const recovery = item.recovery_report || {};
  const fragments = recovery.text_fragments?.length
    ? recovery.text_fragments
    : diagnosis.fragment_samples?.length
      ? diagnosis.fragment_samples
      : (diagnosis.image_candidates || []).map(candidate =>
        `Image candidate at offset ${candidate.offset} (${candidate.length} bytes; ${candidate.complete ? 'complete marker range' : 'truncated marker range'})`
      ).concat(
        (recovery.fragments || []).map(fragment =>
          `Fragment at offset ${fragment.offset} (${fragment.length} bytes; ${fragment.fragment_status || 'carved'})`
        ),
        item.fragments || []
      );
  const entities = recovery.entities || diagnosis.entities || item.entities || [];
  const graph = recovery.graph || diagnosis.fragment_relationships || null;
  const category = recovery.category || diagnosis.category || item.classification.category;
  const priority = recovery.priority || diagnosis.priority || item.classification.priority;
  const integrity = recovery.integrity_score ?? recovery.confidence ?? diagnosis.integrity_assessment?.score ?? item.health_score;
  item.fragments = fragments;
  item._evidenceGraph = graph;

  const modal = document.getElementById('inspector-modal');
  document.getElementById('modal-filename').textContent = item.file_name;
  document.getElementById('modal-filemeta').textContent = `${formatBytes(item.size_bytes)} • H(x)=${item.entropy} • ${category} • ${fragments.length} evidence fragment(s)`;

  // Entities Bar
  const entitiesBar = document.getElementById('modal-entities-bar');
  if (entities && entities.length > 0) {
    entitiesBar.innerHTML = entities.map(e => `
      <span class="entity-pill">🏷️ ${escapeHtml(e.type)}: <strong>${escapeHtml(e.values.join(', '))}</strong></span>
    `).join('');
  } else {
    entitiesBar.innerHTML = '<span class="entity-pill">🔍 Standard Structured Data</span>';
  }

  // Extracted Text / Code Body
  const textBody = document.getElementById('modal-extracted-text');
  if (item.fragments && item.fragments.length > 0) {
    textBody.innerHTML = item.fragments.map(f => {
      if (f.includes('class ') || f.includes('public ') || f.includes('void ') || f.includes('{') || f.includes('}')) {
        return `<div class="code-block">${escapeHtml(f)}</div>`;
      }
      return `<p style="margin-bottom: 8px;">${escapeHtml(f)}</p>`;
    }).join('');
  } else {
    textBody.innerHTML = '<p style="color: var(--text-muted);">No printable plain-text fragments detected in byte-stream.</p>';
  }

  // Integrity Assessment Tab
  document.getElementById('modal-feasibility-val').textContent = `${integrity}%`;
  document.getElementById('modal-feasibility-bar').style.width = `${integrity}%`;
  document.getElementById('modal-category-val').textContent = category;
  document.getElementById('modal-priority-badge').innerHTML = `
    <span class="badge ${item.classification.priorityClass}">${escapeHtml(priority)} Priority</span>
  `;
  document.getElementById('modal-realism-text').textContent =
    recovery.realism_assessment
    || diagnosis.integrity_assessment?.basis
    || (recovery.deletion_status
      ? `${recovery.deletion_proven ? 'Deletion confirmed' : 'Deletion not proven'} • ${recovery.recovered_percentage == null ? `original coverage unknown; marker range ${recovery.validated_range_percentage == null ? 'incomplete' : `${recovery.validated_range_percentage}% validated`}` : `${recovery.recovered_percentage}% validated coverage`} • ${fragments.length} fragment(s).`
      : `Evidence analysis found ${fragments.length} recoverable fragment(s).`);

  const actionsList = document.getElementById('modal-repair-actions-list');
  const actions = recovery.repair_actions || recovery.operations || [];
  actionsList.innerHTML = (actions.length ? actions : [
    `Pre-recovery analysis found ${fragments.length} fragment(s)`,
    `Relationship graph contains ${graph?.total_nodes || 0} node(s) and ${graph?.total_edges || 0} edge(s)`,
    'Integrity assessed from format markers, fragments, and structural checks',
    ...(recovery.deletion_status ? [
      `Deleted-file status: ${recovery.deletion_proven ? 'confirmed by filesystem metadata' : 'unconfirmed signature carve'}`,
      `Coverage: ${recovery.recovered_percentage == null ? `original allocation unknown; marker range ${recovery.validated_range_percentage == null ? 'incomplete' : `${recovery.validated_range_percentage}% validated`}` : `${recovery.recovered_percentage}%`}`,
    ] : []),
  ]).map(action => `<li>${escapeHtml(action)}</li>`).join('');

  // Hex Viewer
  const hexViewer = document.getElementById('modal-hex-viewer');
  hexViewer.textContent = generateHexDump(item.raw_bytes.slice(0, 512));

  // Render Canvas Graph
  setTimeout(() => drawRelationshipGraph(item), 100);

  modal.style.display = 'flex';
}

function closeInspectorModal() {
  document.getElementById('inspector-modal').style.display = 'none';
}

function switchModalTab(tabId) {
  ['content', 'graph', 'integrity', 'hex'].forEach(t => {
    document.getElementById(`mtab-${t}`).classList.remove('active');
    document.getElementById(`pane-${t}`).classList.remove('active');
  });

  document.getElementById(`mtab-${tabId}`).classList.add('active');
  document.getElementById(`pane-${tabId}`).classList.add('active');

  if (tabId === 'graph') {
    const item = analyzedItems[currentInspectedIndex];
    if (item) setTimeout(() => drawRelationshipGraph(item), 50);
  }
}

// Canvas Relationship Graph Renderer
function drawRelationshipGraph(item) {
  const canvas = document.getElementById('relationship-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const w = canvas.width;
  const h = canvas.height;

  ctx.clearRect(0, 0, w, h);

  // Define Nodes
  const rootNode = { x: w / 2, y: h / 2, label: item.file_name, color: '#00f2fe', r: 24, type: 'root' };
  const catNode = { x: w / 2, y: 70, label: item.classification.category.split(' ').slice(1).join(' '), color: '#8b5cf6', r: 18, type: 'cat' };

  const fragmentNodes = [];
  const frags = item.fragments.slice(0, 6);
  const angleStep = (Math.PI * 2) / Math.max(1, frags.length);

  frags.forEach((f, i) => {
    const angle = i * angleStep;
    const dist = 140;
    fragmentNodes.push({
      x: w / 2 + Math.cos(angle) * dist,
      y: h / 2 + Math.sin(angle) * dist,
      label: `Frag #${i+1}: ${f.slice(0, 16)}...`,
      color: '#10b981',
      r: 14,
      type: 'frag'
    });
  });

  // Draw Edges
  ctx.strokeStyle = 'rgba(0, 242, 254, 0.25)';
  ctx.lineWidth = 1.5;

  // Root to Category
  ctx.beginPath();
  ctx.moveTo(rootNode.x, rootNode.y);
  ctx.lineTo(catNode.x, catNode.y);
  ctx.stroke();

  // Root to Fragments
  fragmentNodes.forEach(fn => {
    ctx.beginPath();
    ctx.moveTo(rootNode.x, rootNode.y);
    ctx.lineTo(fn.x, fn.y);
    ctx.stroke();
  });

  // Draw Nodes
  [rootNode, catNode, ...fragmentNodes].forEach(node => {
    ctx.shadowColor = node.color;
    ctx.shadowBlur = 12;
    ctx.fillStyle = node.color;
    ctx.beginPath();
    ctx.arc(node.x, node.y, node.r, 0, Math.PI * 2);
    ctx.fill();

    ctx.shadowBlur = 0;
    ctx.fillStyle = '#f8fafc';
    ctx.font = '11px Inter, sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText(node.label, node.x, node.y + node.r + 14);
  });
}

function generateHexDump(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i += 16) {
    const chunk = bytes.slice(i, i + 16);
    const hex = Array.from(chunk).map(b => b.toString(16).padStart(2, '0')).join(' ');
    const ascii = Array.from(chunk).map(b => (b >= 32 && b <= 126 ? String.fromCharCode(b) : '.')).join('');
    out += `${i.toString(16).padStart(6, '0')}  ${hex.padEnd(48, ' ')}  |${ascii}|\n`;
  }
  return out;
}

function copyExtractedContent() {
  const item = analyzedItems[currentInspectedIndex];
  if (!item) return;
  const text = item.fragments.join('\n\n');
  navigator.clipboard.writeText(text);
  showToast('Copied all extracted text to clipboard!', 'success');
}

function downloadExtractedMarkdown() {
  const item = analyzedItems[currentInspectedIndex];
  if (!item) return;
  const md = `# Extracted Content: ${item.file_name}\n\nCategory: ${item.classification.category}\n\n---\n\n${item.fragments.join('\n\n')}`;
  const blob = new Blob([md], { type: 'text/markdown' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `${item.file_name.replace(/\.[^/.]+$/, "")}_recovered.md`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  showToast('Saved notes as Markdown file.', 'success');
}

// ==============================================================================
// UTILITIES
// ==============================================================================

function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function escapeHtml(str) {
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function showToast(msg, type = 'info') {
  const root = document.getElementById('toast-root');
  if (!root) return;
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.textContent = msg;
  root.appendChild(toast);
  setTimeout(() => toast.remove(), 4000);
}

async function checkBackendHealth() {
  try {
    const res = await fetch(`${API_BASE_URL}/api/health`);
    if (res.ok) {
      let label = 'Forensic API Online';
      try {
        const ai = await fetch(`${API_BASE_URL}/api/ai/status`).then(response => response.json());
        if (ai.status === 'ready') label += ' • Visual AI Ready';
        else if (ai.status === 'unavailable') label += ' • AI Model Unavailable';
      } catch (_) {
        label += ' • AI Status Unknown';
      }
      document.getElementById('backend-status-label').textContent = label;
    }
  } catch (e) {
    document.getElementById('backend-status-label').textContent = 'In-Browser Forensic Kernel';
  }
}
