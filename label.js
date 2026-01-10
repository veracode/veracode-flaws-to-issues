//
// handle label creation and mgmt
//

const { request } = require('@octokit/request');

const flawLabels = [
    {
        'name': 'VeracodeFlaw: Very High',
        'color': 'd92b85',
        'description': 'A Veracode Flaw, Very High severity',
        'severity': 5
    },
    {
        'name': 'VeracodeFlaw: High',
        'color': 'e61f25',
        'description': 'A Veracode Flaw, High severity',
        'severity': 4
    },
    {
        'name': 'VeracodeFlaw: Medium',
        'color': 'fd7333',
        'description': 'A Veracode Flaw, Medium severity',
        'severity': 3
    },
    {
        'name': 'VeracodeFlaw: Low',
        'color': 'ffcc33',
        'description': 'A Veracode Flaw, Low severity',
        'severity': 2
    },
    {
        'name': 'VeracodeFlaw: Very Low',
        'color': 'c9da2c',
        'description': 'A Veracode Flaw, Very Low severity',
        'severity': 1
    },
    {
        'name': 'VeracodeFlaw: Informational',
        'color': '8dbd3e',
        'description': 'A Veracode Flaw, Informational severity',
        'severity': 0
    }
];

// https://www.color-hex.com
const otherLabels = [
    {
        'id': 'pipeline',
        'name': 'Veracode Pipeline Scan',
        'color': '76a6b6',
        'description': 'A Veracode Flaw found during a Pipeline Scan'
    },
    {
        'id': 'policy',
        'name': 'Veracode Policy Scan',
        'color': '666698',
        'description': 'A Veracode Flaw found during a Policy or Sandbox Scan'
    },
    {
        'id': 'sca',
        'name': 'Veracode-SCA',
        'color': '8b5cf6',
        'description': 'A Veracode Software Composition Analysis (SCA) finding'
    }
];


// create the labels we need to tag issues with
async function createLabels(options) {
    const githubOwner = options.githubOwner;
    const githubRepo = options.githubRepo;
    const githubToken = options.githubToken;

    // create label, accept error code if it already exists
    console.log('Creating VeracodeFlaw labels');

    var authToken = 'Bearer ' + githubToken;

    for(const element of flawLabels.concat(otherLabels) ) {
        await request('POST /repos/{owner}/{repo}/labels', {
            headers: {
                authorization: authToken
            },
            owner: githubOwner,
            repo: githubRepo,
            data: {
                "name": element.name,
                "color": element.color,
                "description": element.description
            }
        })
        .then( result => {
            console.log(`VeracodeFlaw label \"${element.name}\" successfully created, result: ${result.status}`);
        })
        .catch( error => {
            // 422 (Unprocessable Entity) = label exists
            if(error.status == 422) {
                console.warn(`VeracodeFlaw label \"${element.name}\" probably exists, (Ignored error: ${error.message})`);
            } else {
                throw new Error (`Error ${error.status} creating VeracodeFlaw label \"${element.name}\": ${error.message}`);
            }           
        });
    }
}


var severityXref = new Map();       // for faster lookups, map severity # to text string

function buildSeverityXref() {
    flawLabels.forEach( element => {
        severityXref.set(element.severity, element.name)
    })
}

function severityToLabel(sevNumber) {
    return severityXref.get(sevNumber);
}

// function setupLabels(options) {
//     createLabels(options);

//     buildSeverityXref();
// }

module.exports = { flawLabels, otherLabels, createLabels, buildSeverityXref, severityToLabel };