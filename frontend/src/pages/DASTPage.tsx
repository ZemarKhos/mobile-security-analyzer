/**
 * DAST/Frida Templates Browser Page
 * Browse, combine and download Frida bypass scripts
 */

import { useEffect, useState } from 'react';
import {
  Cpu, Shield, Lock, Smartphone, Search, Copy, Download,
  CheckCircle, Filter, Loader2, Play, Terminal, Zap, Globe
} from 'lucide-react';
import {
  getFridaTemplates, getFridaCategories, getFridaTemplate,
  combineFridaTemplates, getQuickstartScript,
  getCryptoTraceScript, getNetworkTraceScript
} from '@/lib/api';
import type { FridaTemplate } from '@/types/api';
import LoadingSpinner from '@/components/LoadingSpinner';
import { cn } from '@/lib/utils';

interface Category {
  id: string;
  name: string;
  count: number;
}

export default function DASTPage() {
  const [templates, setTemplates] = useState<FridaTemplate[]>([]);
  const [categories, setCategories] = useState<Category[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedCategory, setSelectedCategory] = useState<string>('');
  const [selectedPlatform, setSelectedPlatform] = useState<string>('');
  const [selectedTemplates, setSelectedTemplates] = useState<string[]>([]);
  const [combinedScript, setCombinedScript] = useState<string | null>(null);
  const [combining, setCombining] = useState(false);
  const [copied, setCopied] = useState(false);

  // Trace script states
  const [traceScript, setTraceScript] = useState<string | null>(null);
  const [traceLoading, setTraceLoading] = useState(false);
  const [traceCopied, setTraceCopied] = useState(false);

  // View template detail
  const [viewingTemplate, setViewingTemplate] = useState<FridaTemplate | null>(null);

  useEffect(() => {
    loadData();
  }, []);

  useEffect(() => {
    loadTemplates();
  }, [selectedCategory, selectedPlatform]);

  const loadData = async () => {
    try {
      setLoading(true);
      const [templatesData, categoriesData] = await Promise.all([
        getFridaTemplates(),
        getFridaCategories(),
      ]);
      setTemplates(templatesData);
      setCategories(categoriesData.categories);
    } catch (err) {
      console.error('Failed to load DAST data:', err);
    } finally {
      setLoading(false);
    }
  };

  const loadTemplates = async () => {
    try {
      const data = await getFridaTemplates(
        selectedCategory || undefined,
        selectedPlatform || undefined
      );
      setTemplates(data);
    } catch (err) {
      console.error('Failed to load templates:', err);
    }
  };

  const handleViewTemplate = async (templateId: string) => {
    try {
      const template = await getFridaTemplate(templateId);
      setViewingTemplate(template);
    } catch (err) {
      console.error('Failed to load template:', err);
    }
  };

  const handleToggleSelect = (templateId: string) => {
    setSelectedTemplates(prev =>
      prev.includes(templateId)
        ? prev.filter(id => id !== templateId)
        : [...prev, templateId]
    );
  };

  const handleCombine = async () => {
    if (selectedTemplates.length === 0) return;
    try {
      setCombining(true);
      const result = await combineFridaTemplates(selectedTemplates);
      setCombinedScript(result.script);
    } catch (err) {
      console.error('Failed to combine templates:', err);
    } finally {
      setCombining(false);
    }
  };

  const handleCopyScript = async (script: string) => {
    await navigator.clipboard.writeText(script);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownloadScript = (script: string, filename: string) => {
    const blob = new Blob([script], { type: 'text/javascript' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleTraceScript = async (type: 'crypto' | 'network', platform: string) => {
    try {
      setTraceLoading(true);
      const result = type === 'crypto'
        ? await getCryptoTraceScript(platform)
        : await getNetworkTraceScript(platform);
      setTraceScript(result.script);
    } catch (err) {
      console.error('Failed to load trace script:', err);
    } finally {
      setTraceLoading(false);
    }
  };

  const getCategoryIcon = (categoryId: string) => {
    switch (categoryId) {
      case 'root_detection':
      case 'jailbreak_detection':
        return Shield;
      case 'ssl_pinning':
        return Lock;
      case 'emulator_detection':
        return Smartphone;
      case 'traffic_interception':
        return Globe;
      default:
        return Cpu;
    }
  };

  if (loading) {
    return (
      <div className="flex justify-center py-12">
        <LoadingSpinner size="lg" text="Loading DAST templates..." />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white flex items-center gap-2">
            <Cpu className="h-7 w-7 text-purple-600" />
            DAST / Frida Templates
          </h1>
          <p className="text-gray-500 dark:text-gray-400 mt-1">
            Browse and combine Frida bypass scripts for dynamic analysis
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-sm text-gray-500 dark:text-gray-400">
            {templates.length} templates available
          </span>
        </div>
      </div>

      {/* Filters */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-4">
        <div className="flex items-center gap-4">
          <Filter className="h-5 w-5 text-gray-400" />

          <select
            value={selectedCategory}
            onChange={(e) => setSelectedCategory(e.target.value)}
            className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
          >
            <option value="">All Categories</option>
            {categories.map(cat => (
              <option key={cat.id} value={cat.id}>
                {cat.name} ({cat.count})
              </option>
            ))}
          </select>

          <select
            value={selectedPlatform}
            onChange={(e) => setSelectedPlatform(e.target.value)}
            className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
          >
            <option value="">All Platforms</option>
            <option value="android">Android</option>
            <option value="ios">iOS</option>
          </select>

          {selectedTemplates.length > 0 && (
            <div className="ml-auto flex items-center gap-2">
              <span className="text-sm text-blue-600 dark:text-blue-400">
                {selectedTemplates.length} selected
              </span>
              <button
                onClick={handleCombine}
                disabled={combining}
                className="flex items-center gap-2 px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 disabled:opacity-50"
              >
                {combining ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <Zap className="h-4 w-4" />
                )}
                Combine Selected
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Templates Grid */}
      <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-4">
        {templates.map(template => {
          const Icon = getCategoryIcon(template.category);
          const isSelected = selectedTemplates.includes(template.id);

          return (
            <div
              key={template.id}
              className={cn(
                "bg-white dark:bg-gray-800 rounded-lg shadow p-4 border-2 transition-all cursor-pointer",
                isSelected
                  ? "border-purple-500 dark:border-purple-400"
                  : "border-transparent hover:border-gray-300 dark:hover:border-gray-600"
              )}
            >
              <div className="flex items-start justify-between">
                <div className="flex items-center gap-2">
                  <Icon className={cn(
                    "h-5 w-5",
                    template.platform === 'android' ? 'text-green-600' : 'text-blue-600'
                  )} />
                  <h3 className="font-semibold text-gray-900 dark:text-white">
                    {template.name}
                  </h3>
                </div>
                <input
                  type="checkbox"
                  checked={isSelected}
                  onChange={() => handleToggleSelect(template.id)}
                  className="h-4 w-4 text-purple-600 rounded"
                />
              </div>

              <p className="text-sm text-gray-500 dark:text-gray-400 mt-2 line-clamp-2">
                {template.description}
              </p>

              <div className="flex items-center gap-2 mt-3">
                <span className={cn(
                  "text-xs px-2 py-0.5 rounded-full",
                  template.platform === 'android'
                    ? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200'
                    : 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200'
                )}>
                  {template.platform}
                </span>
                <span className="text-xs px-2 py-0.5 rounded-full bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-300">
                  {template.category.replace(/_/g, ' ')}
                </span>
              </div>

              <button
                onClick={() => handleViewTemplate(template.id)}
                className="mt-3 w-full text-sm text-purple-600 dark:text-purple-400 hover:underline"
              >
                View Script
              </button>
            </div>
          );
        })}
      </div>

      {/* Combined Script Output */}
      {combinedScript && (
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
              Combined Script ({selectedTemplates.length} templates)
            </h3>
            <div className="flex gap-2">
              <button
                onClick={() => handleCopyScript(combinedScript)}
                className="px-3 py-1.5 text-sm bg-gray-100 hover:bg-gray-200 dark:bg-gray-700 dark:hover:bg-gray-600 dark:text-white rounded flex items-center gap-1"
              >
                <Copy className="w-4 h-4" />
                {copied ? 'Copied!' : 'Copy'}
              </button>
              <button
                onClick={() => handleDownloadScript(combinedScript, 'combined_bypass.js')}
                className="px-3 py-1.5 text-sm bg-gray-100 hover:bg-gray-200 dark:bg-gray-700 dark:hover:bg-gray-600 dark:text-white rounded flex items-center gap-1"
              >
                <Download className="w-4 h-4" />
                Download
              </button>
            </div>
          </div>
          <pre className="bg-gray-900 text-green-400 font-mono text-sm p-4 rounded-lg overflow-x-auto max-h-[500px] overflow-y-auto">
            {combinedScript}
          </pre>
        </div>
      )}

      {/* Trace Scripts Section */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4 flex items-center gap-2">
          <Terminal className="w-5 h-5 text-orange-500" />
          Trace Scripts
        </h3>
        <p className="text-sm text-gray-500 dark:text-gray-400 mb-4">
          Runtime tracing scripts for monitoring crypto operations and network traffic
        </p>

        <div className="grid md:grid-cols-2 gap-4">
          <div className="border dark:border-gray-700 rounded-lg p-4">
            <h4 className="font-medium text-gray-900 dark:text-white mb-2">Crypto Trace</h4>
            <p className="text-sm text-gray-500 dark:text-gray-400 mb-3">
              Monitor encryption/decryption operations, key generation, and hashing
            </p>
            <div className="flex gap-2">
              <button
                onClick={() => handleTraceScript('crypto', 'android')}
                disabled={traceLoading}
                className="px-3 py-1.5 text-sm bg-green-100 text-green-700 hover:bg-green-200 dark:bg-green-900 dark:text-green-300 rounded"
              >
                Android
              </button>
              <button
                onClick={() => handleTraceScript('crypto', 'ios')}
                disabled={traceLoading}
                className="px-3 py-1.5 text-sm bg-blue-100 text-blue-700 hover:bg-blue-200 dark:bg-blue-900 dark:text-blue-300 rounded"
              >
                iOS
              </button>
            </div>
          </div>

          <div className="border dark:border-gray-700 rounded-lg p-4">
            <h4 className="font-medium text-gray-900 dark:text-white mb-2">Network Trace</h4>
            <p className="text-sm text-gray-500 dark:text-gray-400 mb-3">
              Monitor HTTP/HTTPS requests, socket connections, and DNS queries
            </p>
            <div className="flex gap-2">
              <button
                onClick={() => handleTraceScript('network', 'android')}
                disabled={traceLoading}
                className="px-3 py-1.5 text-sm bg-green-100 text-green-700 hover:bg-green-200 dark:bg-green-900 dark:text-green-300 rounded"
              >
                Android
              </button>
              <button
                onClick={() => handleTraceScript('network', 'ios')}
                disabled={traceLoading}
                className="px-3 py-1.5 text-sm bg-blue-100 text-blue-700 hover:bg-blue-200 dark:bg-blue-900 dark:text-blue-300 rounded"
              >
                iOS
              </button>
            </div>
          </div>
        </div>

        {traceScript && (
          <div className="mt-4">
            <div className="flex items-center justify-between mb-2">
              <h4 className="font-medium text-gray-700 dark:text-gray-300">Trace Script</h4>
              <div className="flex gap-2">
                <button
                  onClick={async () => {
                    await navigator.clipboard.writeText(traceScript);
                    setTraceCopied(true);
                    setTimeout(() => setTraceCopied(false), 2000);
                  }}
                  className="px-3 py-1.5 text-sm bg-gray-100 hover:bg-gray-200 dark:bg-gray-700 dark:hover:bg-gray-600 dark:text-white rounded flex items-center gap-1"
                >
                  <Copy className="w-4 h-4" />
                  {traceCopied ? 'Copied!' : 'Copy'}
                </button>
                <button
                  onClick={() => handleDownloadScript(traceScript, 'trace_script.js')}
                  className="px-3 py-1.5 text-sm bg-gray-100 hover:bg-gray-200 dark:bg-gray-700 dark:hover:bg-gray-600 dark:text-white rounded flex items-center gap-1"
                >
                  <Download className="w-4 h-4" />
                  Download
                </button>
              </div>
            </div>
            <pre className="bg-gray-900 text-green-400 font-mono text-sm p-4 rounded-lg overflow-x-auto max-h-[400px] overflow-y-auto">
              {traceScript}
            </pre>
          </div>
        )}
      </div>

      {/* Template Detail Modal */}
      {viewingTemplate && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl max-w-4xl w-full max-h-[90vh] overflow-hidden">
            <div className="p-6 border-b dark:border-gray-700">
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="text-xl font-bold text-gray-900 dark:text-white">
                    {viewingTemplate.name}
                  </h2>
                  <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
                    {viewingTemplate.description}
                  </p>
                </div>
                <button
                  onClick={() => setViewingTemplate(null)}
                  className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-200"
                >
                  <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </button>
              </div>
            </div>

            <div className="p-6 overflow-y-auto max-h-[60vh]">
              <div className="flex items-center gap-2 mb-4">
                <span className={cn(
                  "text-xs px-2 py-0.5 rounded-full",
                  viewingTemplate.platform === 'android'
                    ? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200'
                    : 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200'
                )}>
                  {viewingTemplate.platform}
                </span>
                <span className="text-xs px-2 py-0.5 rounded-full bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-300">
                  {viewingTemplate.category.replace(/_/g, ' ')}
                </span>
              </div>

              {viewingTemplate.script && (
                <pre className="bg-gray-900 text-green-400 font-mono text-sm p-4 rounded-lg overflow-x-auto">
                  {viewingTemplate.script}
                </pre>
              )}
            </div>

            <div className="p-6 border-t dark:border-gray-700 flex justify-end gap-2">
              <button
                onClick={() => viewingTemplate.script && handleCopyScript(viewingTemplate.script)}
                className="px-4 py-2 bg-gray-100 hover:bg-gray-200 dark:bg-gray-700 dark:hover:bg-gray-600 dark:text-white rounded-lg flex items-center gap-2"
              >
                <Copy className="w-4 h-4" />
                Copy Script
              </button>
              <button
                onClick={() => viewingTemplate.script && handleDownloadScript(viewingTemplate.script, `${viewingTemplate.id}.js`)}
                className="px-4 py-2 bg-purple-600 text-white hover:bg-purple-700 rounded-lg flex items-center gap-2"
              >
                <Download className="w-4 h-4" />
                Download
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
