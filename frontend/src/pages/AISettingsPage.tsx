/**
 * AI Settings Page
 * Configure AI providers for Frida script generation
 */

import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { ArrowLeft, Bot, Check, AlertCircle, Loader2, Trash2, ExternalLink } from 'lucide-react';
import { 
  getAIProviders, 
  getAIConfig, 
  updateAIConfig, 
  deleteAIConfig, 
  testAIConnection,
  type AIProvider,
  type AIConfig,
} from '@/lib/api';

export default function AISettingsPage() {
  const [providers, setProviders] = useState<AIProvider[]>([]);
  const [currentConfig, setCurrentConfig] = useState<AIConfig | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{ success: boolean; message: string } | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Form state
  const [selectedProvider, setSelectedProvider] = useState<string>('');
  const [apiKey, setApiKey] = useState('');
  const [baseUrl, setBaseUrl] = useState('');
  const [model, setModel] = useState('');
  const [temperature, setTemperature] = useState(0.7);
  const [maxTokens, setMaxTokens] = useState(4096);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      setLoading(true);
      const [providersRes, configRes] = await Promise.all([
        getAIProviders(),
        getAIConfig(),
      ]);
      setProviders(providersRes.providers);
      setCurrentConfig(configRes);

      // If configured, set form values
      if (configRes.configured && configRes.provider) {
        setSelectedProvider(configRes.provider);
        setModel(configRes.model || '');
        if (configRes.base_url) {
          setBaseUrl(configRes.base_url);
        }
      }
    } catch (err) {
      setError('Failed to load AI settings');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleProviderChange = (providerId: string) => {
    setSelectedProvider(providerId);
    setTestResult(null);
    
    const provider = providers.find(p => p.id === providerId);
    if (provider) {
      setModel(provider.default_model);
      if (provider.default_base_url) {
        setBaseUrl(provider.default_base_url);
      } else {
        setBaseUrl('');
      }
      setApiKey('');
    }
  };

  const handleSave = async () => {
    try {
      setSaving(true);
      setError(null);
      setTestResult(null);

      await updateAIConfig({
        provider: selectedProvider,
        api_key: apiKey || undefined,
        base_url: baseUrl || undefined,
        model,
        temperature,
        max_tokens: maxTokens,
      });

      // Reload config
      const configRes = await getAIConfig();
      setCurrentConfig(configRes);
      setTestResult({ success: true, message: 'Configuration saved successfully!' });
    } catch (err: any) {
      setError(err.message || 'Failed to save configuration');
    } finally {
      setSaving(false);
    }
  };

  const handleTest = async () => {
    try {
      setTesting(true);
      setTestResult(null);
      setError(null);

      const result = await testAIConnection();
      setTestResult(result);
    } catch (err: any) {
      setTestResult({ success: false, message: err.message || 'Connection test failed' });
    } finally {
      setTesting(false);
    }
  };

  const handleDelete = async () => {
    if (!confirm('Are you sure you want to remove AI configuration?')) return;

    try {
      await deleteAIConfig();
      setCurrentConfig({ configured: false });
      setSelectedProvider('');
      setApiKey('');
      setBaseUrl('');
      setModel('');
      setTestResult(null);
    } catch (err: any) {
      setError(err.message || 'Failed to delete configuration');
    }
  };

  const selectedProviderInfo = providers.find(p => p.id === selectedProvider);

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <Loader2 className="w-8 h-8 animate-spin text-blue-600" />
      </div>
    );
  }

  return (
    <div className="max-w-4xl mx-auto p-6">
      {/* Header */}
      <div className="mb-8">
        <Link to="/" className="inline-flex items-center text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-200 mb-4">
          <ArrowLeft className="w-4 h-4 mr-2" />
          Back to Home
        </Link>
        <div className="flex items-center gap-3">
          <div className="p-3 bg-purple-100 dark:bg-purple-900/50 rounded-lg">
            <Bot className="w-8 h-8 text-purple-600 dark:text-purple-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">AI Settings</h1>
            <p className="text-gray-600 dark:text-gray-400">Configure AI for Frida bypass script generation</p>
          </div>
        </div>
      </div>

      {/* Current Status */}
      <div className={`mb-6 p-4 rounded-lg ${currentConfig?.configured ? 'bg-green-50 dark:bg-green-900/30 border border-green-200 dark:border-green-800' : 'bg-yellow-50 dark:bg-yellow-900/30 border border-yellow-200 dark:border-yellow-800'}`}>
        <div className="flex items-center gap-2">
          {currentConfig?.configured ? (
            <>
              <Check className="w-5 h-5 text-green-600 dark:text-green-400" />
              <span className="font-medium text-green-800 dark:text-green-300">
                AI Configured: {currentConfig.provider} / {currentConfig.model}
              </span>
            </>
          ) : (
            <>
              <AlertCircle className="w-5 h-5 text-yellow-600 dark:text-yellow-400" />
              <span className="font-medium text-yellow-800 dark:text-yellow-300">
                AI not configured. Configure below to enable Frida script generation.
              </span>
            </>
          )}
        </div>
      </div>

      {/* Error Message */}
      {error && (
        <div className="mb-6 p-4 bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800 rounded-lg text-red-700 dark:text-red-300">
          {error}
        </div>
      )}

      {/* Test Result */}
      {testResult && (
        <div className={`mb-6 p-4 rounded-lg ${testResult.success ? 'bg-green-50 dark:bg-green-900/30 border border-green-200 dark:border-green-800' : 'bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800'}`}>
          <div className="flex items-center gap-2">
            {testResult.success ? (
              <Check className="w-5 h-5 text-green-600 dark:text-green-400" />
            ) : (
              <AlertCircle className="w-5 h-5 text-red-600 dark:text-red-400" />
            )}
            <span className={testResult.success ? 'text-green-700 dark:text-green-300' : 'text-red-700 dark:text-red-300'}>
              {testResult.message}
            </span>
          </div>
        </div>
      )}

      {/* Provider Selection */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6 mb-6">
        <h2 className="text-lg font-semibold mb-4 text-gray-900 dark:text-white">Select AI Provider</h2>
        
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {providers.map(provider => (
            <button
              key={provider.id}
              onClick={() => handleProviderChange(provider.id)}
              className={`p-4 rounded-lg border-2 text-left transition-all ${
                selectedProvider === provider.id
                  ? 'border-blue-500 bg-blue-50 dark:bg-blue-900/30'
                  : 'border-gray-200 dark:border-gray-600 hover:border-gray-300 dark:hover:border-gray-500 bg-white dark:bg-gray-800'
              }`}
            >
              <div className="font-medium text-gray-900 dark:text-white">{provider.name}</div>
              <div className="text-sm text-gray-500 dark:text-gray-400 mt-1">{provider.description}</div>
              <div className="flex gap-2 mt-2">
                {provider.requires_api_key && (
                  <span className="text-xs bg-yellow-100 dark:bg-yellow-900/50 text-yellow-700 dark:text-yellow-300 px-2 py-0.5 rounded">
                    API Key
                  </span>
                )}
                {!provider.requires_api_key && (
                  <span className="text-xs bg-green-100 dark:bg-green-900/50 text-green-700 dark:text-green-300 px-2 py-0.5 rounded">
                    Local
                  </span>
                )}
              </div>
            </button>
          ))}
        </div>
      </div>

      {/* Configuration Form */}
      {selectedProvider && selectedProviderInfo && (
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6 mb-6">
          <h2 className="text-lg font-semibold mb-4 text-gray-900 dark:text-white">
            Configure {selectedProviderInfo.name}
          </h2>

          <div className="space-y-4">
            {/* API Key */}
            {selectedProviderInfo.requires_api_key && (
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  API Key <span className="text-red-500">*</span>
                </label>
                <input
                  type="password"
                  value={apiKey}
                  onChange={(e) => setApiKey(e.target.value)}
                  placeholder="Enter your API key"
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                />
                <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                  {selectedProvider === 'openai' && (
                    <>Get your API key from <a href="https://platform.openai.com/api-keys" target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">OpenAI Platform <ExternalLink className="w-3 h-3 inline" /></a></>
                  )}
                  {selectedProvider === 'anthropic' && (
                    <>Get your API key from <a href="https://console.anthropic.com/" target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">Anthropic Console <ExternalLink className="w-3 h-3 inline" /></a></>
                  )}
                </p>
              </div>
            )}

            {/* Base URL */}
            {selectedProviderInfo.requires_base_url && (
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Base URL <span className="text-red-500">*</span>
                </label>
                <input
                  type="text"
                  value={baseUrl}
                  onChange={(e) => setBaseUrl(e.target.value)}
                  placeholder={selectedProviderInfo.default_base_url || "Enter API base URL"}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                />
                <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                  Default: {selectedProviderInfo.default_base_url}
                </p>
              </div>
            )}

            {/* Model */}
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Model
              </label>
              {selectedProviderInfo.models.length > 0 ? (
                <select
                  value={model}
                  onChange={(e) => setModel(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                >
                  {selectedProviderInfo.models.map(m => (
                    <option key={m} value={m}>{m}</option>
                  ))}
                </select>
              ) : (
                <input
                  type="text"
                  value={model}
                  onChange={(e) => setModel(e.target.value)}
                  placeholder="Enter model name"
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                />
              )}
            </div>

            {/* Advanced Settings */}
            <details className="mt-4">
              <summary className="cursor-pointer text-sm font-medium text-gray-700 dark:text-gray-300">
                Advanced Settings
              </summary>
              <div className="mt-4 space-y-4 pl-4 border-l-2 border-gray-200 dark:border-gray-600">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Temperature ({temperature})
                  </label>
                  <input
                    type="range"
                    min="0"
                    max="2"
                    step="0.1"
                    value={temperature}
                    onChange={(e) => setTemperature(parseFloat(e.target.value))}
                    className="w-full"
                  />
                  <p className="text-xs text-gray-500 dark:text-gray-400">
                    Lower = more focused, Higher = more creative
                  </p>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Max Tokens
                  </label>
                  <input
                    type="number"
                    value={maxTokens}
                    onChange={(e) => setMaxTokens(parseInt(e.target.value))}
                    min={100}
                    max={32000}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                  />
                </div>
              </div>
            </details>
          </div>

          {/* Actions */}
          <div className="flex gap-3 mt-6 pt-4 border-t border-gray-200 dark:border-gray-700">
            <button
              onClick={handleSave}
              disabled={saving || (selectedProviderInfo.requires_api_key && !apiKey)}
              className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
            >
              {saving ? <Loader2 className="w-4 h-4 animate-spin" /> : <Check className="w-4 h-4" />}
              Save Configuration
            </button>

            {currentConfig?.configured && (
              <>
                <button
                  onClick={handleTest}
                  disabled={testing}
                  className="px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 disabled:opacity-50 flex items-center gap-2"
                >
                  {testing ? <Loader2 className="w-4 h-4 animate-spin" /> : null}
                  Test Connection
                </button>

                <button
                  onClick={handleDelete}
                  className="px-4 py-2 bg-red-100 text-red-700 rounded-lg hover:bg-red-200 flex items-center gap-2"
                >
                  <Trash2 className="w-4 h-4" />
                  Remove
                </button>
              </>
            )}
          </div>
        </div>
      )}

      {/* Instructions */}
      <div className="bg-gray-50 dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
        <h2 className="text-lg font-semibold mb-3 text-gray-900 dark:text-white">How It Works</h2>
        <ol className="list-decimal list-inside space-y-2 text-gray-600 dark:text-gray-400">
          <li>Configure an AI provider above (local or cloud)</li>
          <li>Analyze an APK file using Mobile Analyzer</li>
          <li>Go to the report and click "Security Mechanisms" tab</li>
          <li>Click "Generate Frida Bypass Script" to create automated bypass code</li>
          <li>Copy the generated script and use with Frida</li>
        </ol>

        <div className="mt-4 p-4 bg-blue-50 dark:bg-blue-900/30 rounded-lg border border-blue-100 dark:border-blue-800">
          <h3 className="font-medium text-blue-900 dark:text-blue-300">Recommended for Best Results</h3>
          <ul className="mt-2 text-sm text-blue-800 dark:text-blue-300 space-y-1">
            <li>• <strong>Cloud:</strong> GPT-4 or Claude 3 Opus for most accurate scripts</li>
            <li>• <strong>Local:</strong> DeepSeek Coder or CodeLlama for code generation</li>
            <li>• Higher token limits (8k+) for complex APKs with many detections</li>
          </ul>
        </div>
      </div>
    </div>
  );
}
