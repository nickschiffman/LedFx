import React from 'react';
// import PropTypes from 'prop-types';
import { SchemaForm } from 'react-schema-form';
// import clsx from 'clsx';
import withStyles from '@material-ui/core/styles/withStyles';
import Button from '@material-ui/core/Button';
import DialogActions from '@material-ui/core/DialogActions';
import Box from '@material-ui/core/Box';
// import ExpandMoreIcon from '@material-ui/icons/ExpandMore';
import Dialog from '@material-ui/core/Dialog';
import DialogContent from '@material-ui/core/DialogContent';
import DialogTitle from '@material-ui/core/DialogTitle';
import DialogContentText from '@material-ui/core/DialogContentText';

// import DropDown from 'components/forms/DropDown';
// import AdditionalProperties from './AdditionalProperties';

const styles = theme => ({
    form: {
        display: 'flex',
        flexWrap: 'wrap',
    },
    schemaForm: {
        display: 'flex',
        flexWrap: 'wrap',
        width: '100%',
    },
    bottomContainer: {
        flex: 1,
        marginTop: 8,
    },
    actionButtons: {
        '& > *': {
            marginLeft: theme.spacing(2),
        },
    },
    expandIcon: {
        transform: 'rotate(180deg)',
    },
});

class DisplayConfigDialog extends React.Component {
    constructor(props) {
        super(props);

        this.state = {
            model: {},
            additionalPropertiesOpen: false,
        };
    }

    handleCancel = () => {
        this.props.onClose();
    };

    handleSubmit = () => {
        const { initial, onAddDisplay, onUpdateDisplay } = this.props;
        const { model: config } = this.state;

        if (initial.id) {
            onUpdateDisplay(initial.id, config);
        } else {
            onAddDisplay(config);
        }

        this.props.onClose();
    };

    render() {
        const { classes, open, displays } = this.props;
        const { model } = this.state;
        console.log(displays);
        const currentSchema = {
            title: 'Configuration',
            properties: {},
            ...(displays ? displays.schema : {}),
        };

        console.log(currentSchema);
        const requiredKeys = currentSchema.required;
        const optionalKeys = Object.keys(currentSchema.properties).filter(
            key => !(requiredKeys && requiredKeys.some(rk => key === rk))
        );
        return (
            <Dialog
                onClose={this.handleClose}
                className={classes.cardResponsive}
                aria-labelledby="form-dialog-title"
                disableBackdropClick
                open={open}
            >
                <DialogTitle id="form-dialog-title">Add Display</DialogTitle>
                <DialogContent className={classes.cardResponsive}>
                    <DialogContentText>
                        To add a device to LedFx, please first select the type of device you wish to
                        add then provide the necessary configuration.
                    </DialogContentText>
                    <form onSubmit={this.handleSubmit} className={classes.form}>
                        <SchemaForm
                            className={classes.schemaForm}
                            schema={currentSchema}
                            form={(requiredKeys, optionalKeys)}
                            model={model}
                        />

                        <DialogActions className={classes.bottomContainer}>
                            <Box
                                flex={1}
                                display="flex"
                                justifyContent="flex-end"
                                className={classes.actionButtons}
                            >
                                <Button
                                    className={classes.button}
                                    onClick={this.handleCancel}
                                    color="primary"
                                >
                                    {'Cancel'}
                                </Button>
                                <Button
                                    className={classes.button}
                                    type="submit"
                                    variant="contained"
                                    color="primary"
                                >
                                    {'Submit'}
                                </Button>
                            </Box>
                        </DialogActions>
                    </form>
                </DialogContent>
            </Dialog>
        );
    }
}

export default withStyles(styles)(DisplayConfigDialog);
