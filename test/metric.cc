// Copyright (C) 2021 Institute of Data Security, HIT
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifdef ENABLE_OPENTELEMETRY_API
#include "opentelemetry/exporters/ostream/metric_exporter.h"
#include "opentelemetry/metrics/provider.h"
#include "opentelemetry/sdk/metrics/meter.h"
#include "opentelemetry/sdk/metrics/meter_provider.h"
#include "opentelemetry/sdk/metrics/export/periodic_exporting_metric_reader.h"
#ifdef ENABLE_PROMETHEUS
#include "opentelemetry/exporters/prometheus/exporter.h"
#endif

void initMetrics() {
  /**
   * step1: Initialize an exporter and a reader. In this case, we initialize an OStream Exporter 
   * which will print to stdout by default. The reader periodically collects metrics from the 
   * Aggregation Store and exports them.
   */
#ifdef ENABLE_PROMETHEUS  // exported via prometheus
  opentelemetry::exporter::metrics::PrometheusExporterOptions opts;
  opts.url = "localhost:9464"; // listen on localhost:9464

  std::unique_ptr<opentelemetry::sdk::metrics::PushMetricExporter> exporter{
      new opentelemetry::exporter::metrics::PrometheusExporter(opts)};
#else // exported via stdout
  std::unique_ptr<opentelemetry::sdk::metrics::PushMetricExporter> exporter{
      new opentelemetry::exporter::metrics::OStreamMetricExporter};
#endif

  opentelemetry::sdk::metrics::PeriodicExportingMetricReaderOptions options;
  options.export_interval_millis = std::chrono::milliseconds(1000);
  options.export_timeout_millis = std::chrono::milliseconds(100);
  std::unique_ptr<opentelemetry::sdk::metrics::MetricReader> reader{
      new opentelemetry::sdk::metrics::PeriodicExportingMetricReader(std::move(exporter), options)};

  /**
   * step2: Initialize a MeterProvider and add the reader. We will use this to obtain Meter objects 
   * in the future.
   */
  auto provider = std::shared_ptr<opentelemetry::metrics::MeterProvider>(
      new opentelemetry::sdk::metrics::MeterProvider());
  auto p = std::static_pointer_cast<opentelemetry::sdk::metrics::MeterProvider>(provider);
  p->AddMetricReader(std::move(reader));

  /**
   * Optional: Create a view to map the Counter Instrument to Sum Aggregation. Add this view to 
   * provider. View creation is optional unless we want to add custom aggregation config, and 
   * attribute processor. Metrics SDK will implicitly create a missing view with default mapping 
   * between Instrument and Aggregation.
   */
  std::unique_ptr<opentelemetry::sdk::metrics::InstrumentSelector> instrument_selector{
      new opentelemetry::sdk::metrics::InstrumentSelector(
          opentelemetry::sdk::metrics::InstrumentType::kCounter, "*")};
  std::unique_ptr<opentelemetry::sdk::metrics::MeterSelector> meter_selector{
      new opentelemetry::sdk::metrics::MeterSelector("", "", "")};
  std::unique_ptr<opentelemetry::sdk::metrics::View> sum_view{
      new opentelemetry::sdk::metrics::View{"sdf_invoked_counter", "SDF invoked counter",
                                            opentelemetry::sdk::metrics::AggregationType::kSum}};
  p->AddView(std::move(instrument_selector), std::move(meter_selector), std::move(sum_view));

  /**
   * Optional: Create a view to map the Histogram Instrument to Histogram Aggregation.
   */
  std::unique_ptr<opentelemetry::sdk::metrics::InstrumentSelector> histogram_instrument_selector{
      new opentelemetry::sdk::metrics::InstrumentSelector(
          opentelemetry::sdk::metrics::InstrumentType::kHistogram, "*")};
  std::unique_ptr<opentelemetry::sdk::metrics::MeterSelector> histogram_meter_selector{
      new opentelemetry::sdk::metrics::MeterSelector("", "", "")};
  std::shared_ptr<opentelemetry::sdk::metrics::AggregationConfig> aggregation_config{
      new opentelemetry::sdk::metrics::HistogramAggregationConfig};
  static_cast<opentelemetry::sdk::metrics::HistogramAggregationConfig *>(aggregation_config.get())
      ->boundaries_ = std::list<double>{0.0, 50.0, 100.0, 250.0, 500.0, 750.0,
                                        1000.0, 2500.0, 5000.0, 10000.0, 20000.0};
  std::unique_ptr<opentelemetry::sdk::metrics::View> histogram_view{
      new opentelemetry::sdk::metrics::View{
          "sdf_invoked_latency", "SDF invoked latency",
          opentelemetry::sdk::metrics::AggregationType::kHistogram, aggregation_config}};
  p->AddView(std::move(histogram_instrument_selector), std::move(histogram_meter_selector),
             std::move(histogram_view));

  /**
   * step 3: set the global provider
   */
  opentelemetry::metrics::Provider::SetMeterProvider(provider);
}
#endif