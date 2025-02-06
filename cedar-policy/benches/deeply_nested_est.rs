/*
 * Copyright Cedar Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use cedar_policy::Policy;

use criterion::{black_box, criterion_group, criterion_main, Criterion};

// PANIC SAFETY: benchmarking
#[allow(clippy::unwrap_used)]
pub fn deeply_nested_est(c: &mut Criterion) {
    let json_str = r#"
        {
            "conditions": [
              {
                "kind": "unless",
                "body": {
                  "==": {
                    "left": {
                      "is": [
                        {
                          ">": [
                            {
                              "==": {
                                "left": {
                                  "is": [
                                    {
                                      "+": [
                                        {
                                          ">": [
                                            {
                                              "is": [
                                                {
                                                  "[>": [
                                                    {},
                                                    {
                                                      ">=": {
                                                        "left": {
                                                          "icieaticPHHcPoHtmcPolissaticPolicHHH&HHHs": [],
                                                          "QtsaPolizciessatcPolicieHHHs": [
                                                            {
                                                              "==": {
                                                                "left": {
                                                                  "is": [
                                                                    {
                                                                      ">": [
                                                                        {
                                                                          "==": {
                                                                            "left": {
                                                                              "is": [
                                                                                {
                                                                                  "+": [
                                                                                    {
                                                                                      ">": [
                                                                                        {
                                                                                          "is": [
                                                                                            {
                                                                                              "[>": [
                                                                                                {},
                                                                                                {
                                                                                                  ">=": {
                                                                                                    "left": {
                                                                                                      "HHHHhHcPolictempHHHHmpHH:HHHHs": [],
                                                                                                      "QstaticPolicieaticPHHcPoHsieaticPHHcPoHtmcPolissaticPolicHHH&HHHs": [],
                                                                                                      "QtsaPolizciessatcPolicieHHHs": [
                                                                                                        {
                                                                                                          "==": {
                                                                                                            "left": {
                                                                                                              "is": [
                                                                                                                {
                                                                                                                  ">": [
                                                                                                                    {
                                                                                                                      "==": {
                                                                                                                        "left": {
                                                                                                                          "is": [
                                                                                                                            {
                                                                                                                              "+": [
                                                                                                                                {
                                                                                                                                  ">": [
                                                                                                                                    {
                                                                                                                                      "is": [
                                                                                                                                        {
                                                                                                                                          "[>": [
                                                                                                                                            {},
                                                                                                                                            {
                                                                                                                                              ">=": {
                                                                                                                                                "left": {
                                                                                                                                                  "HHHHhHcPolictempHHHHmpHH:HHHHs": [],
                                                                                                                                                  "QstaticPolicieaticPHHcPoHsaticPolicieaticPHHcPoHsieaticPHHcPoHtmcPolissaticPolicHHH&HHHs": [],
                                                                                                                                                  "QtsaPolizciessatcPolicieHHHs": [ ],
                                                                                                                                                  "Q?tHHHHHHHHHHHHmplates": {},
                                                                                                                                                  "": {},
                                                                                                                                                  "XtLHHHHHHHHHHHHHps2  \temHHclictempHHHHHHHs": [],
                                                                                                                                                  "QstatncPlictempHHHHHHHs": [],
                                                                                                                                                  "QstatncPolicieaticPHHHQstatmcPolicHHHHHHs": [],
                                                                                                                                                  "QstaPoliciessaticPolicHHHHHHs": [],
                                                                                                                                                  "QtsassatcPolicieHHHs": [],
                                                                                                                                                  "Q?tHHHHHHHHHHHHHHHHHHHmplates": {},
                                                                                                                                                  "XtLHHHHHHHHHHHHHHct]is": [ ]
                                                                                                                                                }
                                                                                                                                              }
                                                                                                                                            }
                                                                                                                                          ]
                                                                                                                                        }
                                                                                                                                      ]
                                                                                                                                    }
                                                                                                                                  ]
                                                                                                                                },
                                                                                                                                "-"
                                                                                                                              ]
                                                                                                                            }
                                                                                                                          ]
                                                                                                                        }
                                                                                                                      }
                                                                                                                    }
                                                                                                                  ]
                                                                                                                }
                                                                                                              ]
                                                                                                            }
                                                                                                          }
                                                                                                        }
                                                                                                      ],
                                                                                                      "Q?tHHHHHHHHHHHHmplates": {},
                                                                                                      "": {},
                                                                                                      "XtLHHHHHHHHHHHHHps2  \temHHclictempHHHHHHHs": [],
                                                                                                      "QstatncPol$cieaticPHHHQstatmcPolicHHHHHHs": [],
                                                                                                      "QstaPmliciessaticPolicHHHHHHs": [],
                                                                                                      "QtsassatcPolicieHHHs": [],
                                                                                                      "Q?tHHHHHHHHHHHHHHHHHHHmplates": {},
                                                                                                      "XtLHHHHHHHHHHHHHHct]is": [ ]
                                                                                                    }
                                                                                                  }
                                                                                                }
                                                                                              ]
                                                                                            }
                                                                                          ]
                                                                                        }
                                                                                      ]
                                                                                    },
                                                                                    "-"
                                                                                  ]
                                                                                }
                                                                              ]
                                                                            }
                                                                          }
                                                                        }
                                                                      ]
                                                                    }
                                                                  ]
                                                                }
                                                              }
                                                            }
                                                          ],
                                                          "Q?tHHHHHHHHHHHHmplates": {},
                                                          "": {},
                                                          "XtLHHHHHHHHHHHHHps2  \temHHct]is": [ ]
                                                        }
                                                      }
                                                    }
                                                  ]
                                                }
                                              ]
                                            }
                                          ]
                                        },
                                        "-"
                                      ]
                                    }
                                  ]
                                }
                              }
                            }
                          ]
                        }
                      ]
                    }
                  }
                }
              }
            ]
          }
    "#;

    c.bench_function("Policy::from_json", |b| {
        b.iter(|| {
            let _ = Policy::from_json(
                None,
                black_box(serde_json::from_str(black_box(json_str)).unwrap()),
            );
        })
    });
}

criterion_group!(benches, deeply_nested_est);
criterion_main!(benches);
